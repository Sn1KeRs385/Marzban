import asyncio
import json
import time

import commentjson
from fastapi import APIRouter, Depends, HTTPException, WebSocket
from starlette.websockets import WebSocketDisconnect

from app import xray
from app.db import Session, get_db, crud
from app.models.admin import Admin
from app.models.core import CoreStats
from app.utils import responses
from app.xray import XRayConfig
from config import XRAY_JSON
from sqlalchemy import text
from app.db.models import ProxyInbound, User, Proxy, ProxyTypes
from sqlalchemy.orm import joinedload
from app.db.crud import get_node_by_id

router = APIRouter(tags=["Core"], prefix="/api", responses={401: responses._401})


@router.websocket("/core/logs")
async def core_logs(websocket: WebSocket, db: Session = Depends(get_db)):
    token = websocket.query_params.get("token") or websocket.headers.get(
        "Authorization", ""
    ).removeprefix("Bearer ")
    admin = Admin.get_admin(token, db)
    if not admin:
        return await websocket.close(reason="Unauthorized", code=4401)

    if not admin.is_sudo:
        return await websocket.close(reason="You're not allowed", code=4403)

    interval = websocket.query_params.get("interval")
    if interval:
        try:
            interval = float(interval)
        except ValueError:
            return await websocket.close(reason="Invalid interval value", code=4400)
        if interval > 10:
            return await websocket.close(
                reason="Interval must be more than 0 and at most 10 seconds", code=4400
            )

    await websocket.accept()

    cache = ""
    last_sent_ts = 0
    with xray.core.get_logs() as logs:
        while True:
            if interval and time.time() - last_sent_ts >= interval and cache:
                try:
                    await websocket.send_text(cache)
                except (WebSocketDisconnect, RuntimeError):
                    break
                cache = ""
                last_sent_ts = time.time()

            if not logs:
                try:
                    await asyncio.wait_for(websocket.receive(), timeout=0.2)
                    continue
                except asyncio.TimeoutError:
                    continue
                except (WebSocketDisconnect, RuntimeError):
                    break

            log = logs.popleft()

            if interval:
                cache += f"{log}\n"
                continue

            try:
                await websocket.send_text(log)
            except (WebSocketDisconnect, RuntimeError):
                break


@router.get("/core", response_model=CoreStats)
def get_core_stats(admin: Admin = Depends(Admin.get_current)):
    """Retrieve core statistics such as version and uptime."""
    return CoreStats(
        version=xray.core.version,
        started=xray.core.started,
        logs_websocket=router.url_path_for("core_logs"),
    )


@router.post("/core/restart", responses={403: responses._403})
def restart_core(admin: Admin = Depends(Admin.check_sudo_admin)):
    """Restart the core and all connected nodes."""
    startup_config = xray.config.include_db_users()
    xray.core.restart(startup_config)

    for node_id, node in list(xray.nodes.items()):
        if node.connected:
            xray.operations.restart_node(node_id, startup_config)

    return {}


@router.get("/core/config", responses={403: responses._403})
def get_core_config(admin: Admin = Depends(Admin.check_sudo_admin)) -> dict:
    """Get the current core configuration."""
    with open(XRAY_JSON, "r") as f:
        config = commentjson.loads(f.read())

    return config


def process_inbounds_associations(db: Session, payload: dict):
    """Process inbound associations for all users based on new configuration."""
    # Get all unique inbound tags from database and payload
    db_inbounds = {inbound.tag for inbound in db.query(ProxyInbound).all()}
    payload_inbounds = {inbound["tag"] for inbound in payload.get("inbounds", [])}
    all_inbounds = db_inbounds.union(payload_inbounds)
    
    # Process users in batches of 100
    batch_size = 100
    offset = 0
    delete_queries = []
    replace_queries = []
    
    while True:
        users = (
            db.query(User)
            .options(joinedload(User.proxies))
            .filter(User.proxies.any(Proxy.type == ProxyTypes.VLESS))
            .offset(offset)
            .limit(batch_size)
            .all()
        )
        
        if not users:
            break
            
        for user in users:
            if not user.proxies:
                continue
                
            proxy_id = user.proxies[0].id
            for inbound_tag in all_inbounds:
                if user.username in inbound_tag and inbound_tag in payload_inbounds:
                    # Delete association if username is in inbound tag
                    delete_queries.append(
                        f"DELETE FROM exclude_inbounds_association WHERE proxy_id = {proxy_id} AND inbound_tag = '{inbound_tag}'"
                    )
                else:
                    # Add association if username is not in inbound tag
                    replace_queries.append(
                        (proxy_id, inbound_tag)
                    )
        
        # Execute queries in batches of 100
        if len(delete_queries) + len(replace_queries) >= 100:
            execute_queries(db, delete_queries, replace_queries)
            delete_queries = []
            replace_queries = []
            
        offset += batch_size
    
    # Execute remaining queries
    if delete_queries or replace_queries:
        execute_queries(db, delete_queries, replace_queries)


def execute_queries(db, delete_queries, replace_queries):
    """Execute batch of queries with foreign key checks disabled."""
    db.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
    
    # Execute delete queries if any
    if delete_queries:
        for query in delete_queries:
            db.execute(text(query))
    
    # Execute replace queries in a single batch
    if replace_queries:
        values = ", ".join([f"({proxy_id}, '{inbound_tag}')" for proxy_id, inbound_tag in replace_queries])
        db.execute(text(f"REPLACE INTO exclude_inbounds_association VALUES {values}"))
    
    db.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
    db.commit()


def get_affected_nodes(current_config, new_config):
    """
    Определяет, какие ноды затронуты изменениями конфигурации.
    
    Args:
        current_config (dict): Текущая конфигурация
        new_config (dict): Новая конфигурация
        
    Returns:
        set: Набор имён нод, которые затронуты изменениями
    """
    affected_nodes = set()
    
    if not (current_config and new_config and 
            'inbounds' in current_config and 'inbounds' in new_config):
        return affected_nodes
    
    current_inbounds_by_node = {}
    for inbound in current_config['inbounds']:
        if 'tag' in inbound:
            node_name = inbound['tag'].split('_')[0] if '_' in inbound['tag'] else None
            if node_name:
                current_inbounds_by_node.setdefault(node_name, []).append(inbound['tag'])
    
    new_inbounds_by_node = {}
    for inbound in new_config['inbounds']:
        if 'tag' in inbound:
            node_name = inbound['tag'].split('_')[0] if '_' in inbound['tag'] else None
            if node_name:
                new_inbounds_by_node.setdefault(node_name, []).append(inbound['tag'])
    
    # Определяем, какие ноды изменились
    for node_name in set(list(current_inbounds_by_node.keys()) + list(new_inbounds_by_node.keys())):
        current_tags = set(current_inbounds_by_node.get(node_name, []))
        new_tags = set(new_inbounds_by_node.get(node_name, []))
        
        # Если наборы тегов отличаются, нода изменилась
        if current_tags != new_tags:
            affected_nodes.add(node_name)
        else:
            # Проверяем, изменились ли параметры для тегов этой ноды
            for tag in current_tags:
                current_inbound = next((i for i in current_config['inbounds'] if i.get('tag') == tag), None)
                new_inbound = next((i for i in new_config['inbounds'] if i.get('tag') == tag), None)
                
                if current_inbound != new_inbound:
                    affected_nodes.add(node_name)
                    break
    
    return affected_nodes


@router.put("/core/config", responses={403: responses._403})
def modify_core_config(
    payload: dict, admin: Admin = Depends(Admin.check_sudo_admin), db: Session = Depends(get_db)
) -> dict:
    """Modify the core configuration and restart the core."""

    # Process inbound associations
    process_inbounds_associations(db, payload)
    
    try:
        config = XRayConfig(payload, api_port=xray.config.api_port)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))

    # Читаем текущую конфигурацию для сравнения
    current_config = {}
    try:
        with open(XRAY_JSON, "r") as f:
            current_config = commentjson.loads(f.read())
    except (IOError, json.JSONDecodeError):
        # Если не можем прочитать текущую конфигурацию, будем перезапускать все ноды
        pass

    # Находим ноды, которые изменились
    affected_nodes = get_affected_nodes(current_config, payload)

    xray.config = config
    with open(XRAY_JSON, "w") as f:
        f.write(json.dumps(payload, indent=4))

    startup_config = xray.config.include_db_users()
    xray.core.restart(startup_config)
    
    # Перезапускаем только те ноды, которые изменились, или все, если не удалось определить изменения
    if affected_nodes:
        # Получаем все ноды из базы данных одним запросом
        dbnodes = {node.id: node for node in crud.get_nodes(db)}
        
        for node_id, node in list(xray.nodes.items()):
            if node.connected and node_id in dbnodes:
                dbnode = dbnodes[node_id]
                if dbnode.name in affected_nodes:
                    xray.operations.restart_node(node_id, startup_config)

    xray.hosts.update()

    return payload
