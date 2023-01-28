import sys
sys.dont_write_bytecode = True
import aiohttp_cors

from common import web, jsonify, decrypt_data, fg, attr
from config import Config

## import routes
from routes.general import routes as routes_general
from routes.product import routes as routes_product
from routes.user    import routes as routes_user

## create middlewares
@web.middleware
async def info_middleware(request, handler):
    path = request.method.ljust(8)
    method = request.raw_path.ljust(30)
    info = f'{fg(46)}{path}{attr(0)}{fg(226)}{method}{attr(0)}'
    print(info)

    return await handler(request)

@web.middleware
async def auth_middleware(request, handler):
    request.user = None
    token = request.headers.get('Authorization', None)

    if token:
        try:
            request.user = decrypt_data(token)
        except Exception as e:
            jsonify(error='Bad Request')

    return await handler(request)
'''
async def start_background_tasks(app):
    app['task_name'] = app.loop.create_task(async_function(app))

async def cleanup_background_tasks(app):
    app['task_name'].cancel()
    await app['task_name']
'''

## create app
app = web.Application(
    middlewares=[
        info_middleware,
        auth_middleware,
    ],
    client_max_size = 4 * 1024 * 1024 * 1024,
    debug=Config.debug
)

## add routes
app.add_routes(routes_general)
app.add_routes(routes_product)
app.add_routes(routes_user)

## add background tasks
# app.on_startup.append(start_background_tasks)
# app.on_cleanup.append(cleanup_background_tasks)

## CORS setup
if Config.debug:
    cors = aiohttp_cors.setup(app, defaults={
        '*': aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers='*',
            allow_headers='*',
        )
    })

    ## Configure CORS on all routes.
    for route in list(app.router.routes()):
        cors.add(route)

if __name__ == '__main__':
    web.run_app(app, host=Config.host, port=Config.port)
