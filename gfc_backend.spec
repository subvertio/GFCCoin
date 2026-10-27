# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for GFC Backend
Produces: dist/gfc_backend.exe (single-file Windows executable)

Build command:
    cd C:\GFC-Dev\backend
    pyinstaller gfc_backend.spec --clean
"""

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],  # No data files bundled - data dir created at runtime via config.py
    hiddenimports=[
        # uvicorn internals (frequently missed by PyInstaller)
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.loops.asyncio',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.http.h11_impl',
        'uvicorn.protocols.http.httptools_impl',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'uvicorn.lifespan.off',
        # Application modules
        'config',
        'app_seeds',
        'app_engagement',
        'app_profile',
        'app_podt',
        'blockchain',
        'podt_core',
        'peer_discovery',
        'sync_engine',
        'p2p_service',
        'security',
        'signing',
        'sync_ingest',
        'fingerprint',
        'reposts',
        'PIL.Image',
        # Dependencies
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        'multipart',
        'multipart.multipart',
        'httpx',
        'httpx._transports',
        'httpx._transports.default',
        'anyio',
        'anyio._backends',
        'anyio._backends._asyncio',
        'h11',
        'httptools',
        'starlette',
        'starlette.routing',
        'starlette.middleware',
        'starlette.responses',
        'starlette.staticfiles',
        'pydantic',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Broken/unused modules - exclude to prevent import errors
        'libtorrent',
        'torrent_podt',
        'podt_api',
        'web3',
        'eth_account',
        'dotenv',
        'python-dotenv',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='gfc_backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,  # Console window visible for dev builds (change to False for release)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    icon=None,  # Add GFC icon path here for release builds
)
