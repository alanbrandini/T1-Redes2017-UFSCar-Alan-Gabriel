#!/bin/bash
pkill -f -9 daemon.py
python /usr/lib/cgi-bin/daemon/daemon.py --port 8001 &
python /usr/lib/cgi-bin/daemon/daemon.py --port 8002 &
python /usr/lib/cgi-bin/daemon/daemon.py --port 8003 &
echo "Maquinas executando. Portas utilizadas: 8001, 8002, 8003."