#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import threading
import socket
import datetime
import fnmatch
import json
import os
import csv
from functools import wraps
from io import StringIO
from flask import (
    Flask, render_template_string,
    request, redirect, url_for,
    session, flash, Response
)
from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib import RR, A, QTYPE, RCODE, TXT

CONFIG_FILE = 'config.json'
LOG_LIMIT = 100
ADMIN_USER = 'admin'
ADMIN_PASS = 'admin'

# ---------------------------
# Funciones de persistencia
# ---------------------------
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    # formato: {'bloqueos':[], 'maintenance':False}
    return {'bloqueos': [], 'maintenance': False}

def save_config(cfg):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

# Datos globales
config = load_config()
global_bloqueos = config.get('bloqueos', [])
maintenance_mode = config.get('maintenance', False)
logs = []  # lista de dicts {'ts','client','query','action'}
estadisticas = {}

# ---------------------------
# Patrón wildcard
# ---------------------------
def matches_pattern(name, pattern):
    return fnmatch.fnmatch(name.rstrip('.'), pattern.rstrip('.'))

# ---------------------------
# Comprobar horario
# ---------------------------
def dentro_de_franja(start_str, end_str):
    now = datetime.datetime.now().time()
    try:
        start = datetime.datetime.strptime(start_str, '%H:%M').time()
        end = datetime.datetime.strptime(end_str, '%H:%M').time()
    except Exception:
        return True
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end

# ---------------------------
# Resolver DNS y actualizar estadísticas
# ---------------------------
class MiResolver(BaseResolver):
    def resolve(self, request, handler):
        global maintenance_mode
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client = handler.client_address[0] if hasattr(handler, 'client_address') else 'unknown'
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        domain = str(qname)
        action = 'resolved'
        reply = request.reply()

        # Modo mantenimiento: responder con TXT a todo
        if maintenance_mode:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT('PabloDNS: Estamos en mantenimiento'), ttl=60))
            action = 'maintenance mode'
        else:
            # Intentar cada regla activa
            for item in global_bloqueos:
                if not item.get('enabled', True):
                    continue
                pat = item['pattern']
                ip_redir = item['ip'].strip()
                start = item.get('start', '')
                end = item.get('end', '')
                if matches_pattern(domain, pat):
                    if start and end and not dentro_de_franja(start, end):
                        continue
                    estadisticas[pat] = estadisticas.get(pat, 0) + 1
                    if ip_redir.upper() == 'REFUSED':
                        reply.header.rcode = RCODE.REFUSED
                        action = f'refused @ {pat}'
                    else:
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip_redir), ttl=60))
                        action = f'redirect to {ip_redir} @ {pat}'
                    break
            else:
                try:
                    real_ip = socket.gethostbyname(domain.rstrip('.'))
                    reply = request.reply()
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(real_ip), ttl=60))
                    action = f'resolved external {real_ip}'
                except Exception as e:
                    reply = request.reply()
                    action = f'error {e}'

        logs.append({'ts': ts, 'client': client, 'query': f"{domain} ({qtype})", 'action': action})
        if len(logs) > LOG_LIMIT:
            del logs[:-LOG_LIMIT]
        return reply

# ---------------------------
# DNS en hilo
# ---------------------------
def start_dns():
    resolver = MiResolver()
    logger = DNSLogger(prefix=False)
    server = DNSServer(resolver, port=53, address="0.0.0.0", logger=logger)
    server.start_thread()

# ---------------------------
# Flask config
# ---------------------------
app = Flask(__name__)
app.secret_key = os.urandom(24)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            flash("🔒 ¡Acceso denegado! Primero inicia sesión.", "warning")
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

# ---------------------------
# Plantilla HTML
# ---------------------------
TEMPLATE = '''
<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>DNS Dashboard</title><style>
  body{font-family:sans-serif;margin:2em;} .flash{padding:1em;margin-bottom:1em;border:1px solid #ccc;border-radius:5px;} .flash.warning{background:#fff3cd;} table{border-collapse:collapse;width:100%;margin-bottom:1em;} th,td{border:1px solid #ccc;padding:0.5em;} input,button{padding:0.5em;}
</style></head><body>
  {% with messages = get_flashed_messages(with_categories=true) %}{% for cat,msg in messages %}<div class="flash {{cat}}">{{msg}}</div>{% endfor %}{% endwith %}
  {% if session.logged_in %}
    <h1>🔧 DNS Dashboard (Admin)</h1>
    <a href="{{ url_for('logout') }}" style="float:right">🚪 Logout</a>
    {% if maintenance_mode %}
      <div class="flash warning">🛠️ <strong>Modo mantenimiento activo:</strong> PabloDNS: Estamos en mantenimiento</div>
    {% endif %}
    <p><a href="{{ url_for('toggle_maintenance') }}">{{ 'Desactivar mantenimiento' if maintenance_mode else 'Activar mantenimiento' }}</a></p>
    <h2>Patrones de bloqueo</h2>
    <table><tr><th>Patrón</th><th>IP</th><th>Horario</th><th>Estado</th><th>Acciones</th></tr>
      {% for item in bloqueos %}
      <tr>
        <td>{{item.pattern}}</td><td>{{item.ip}}</td><td>{{item.start or '00:00'}}-{{item.end or '23:59'}}</td>
        <td>{{ '✅' if item.enabled else '❌' }}</td>
        <td>
          <a href="{{url_for('toggle_rule',pattern=item.pattern)}}">{{ 'Deshabilitar' if item.enabled else 'Habilitar' }}</a> |
          <a href="{{url_for('remove_block',pattern=item.pattern)}}">Eliminar</a>
        </td>
      </tr>
      {% endfor %}
    </table>
    <form action="{{ url_for('add_block') }}" method="post">
      <input type="text" name="pattern" placeholder="*.ejemplo.com." required>
      <input type="text" name="ip" placeholder="0.0.0.0 o REFUSED" required><br>
      ⏰ <input type="time" name="start" value="00:00">→<input type="time" name="end" value="23:59"><br>
      <button type="submit">Añadir bloqueo</button>
    </form>

    <h2>Logs recientes</h2>
    <a href="{{ url_for('download_logs') }}">📥 Descargar logs CSV</a>
    <table><tr><th>Hora</th><th>Cliente</th><th>Consulta</th><th>Acción</th></tr>
      {% for e in logs %}
      <tr><td>{{e.ts}}</td><td>{{e.client}}</td><td>{{e.query}}</td><td>{{e.action}}</td></tr>
      {% endfor %}
    </table>

    <h2>📊 Estadísticas de bloqueos</h2>
    <a href="{{ url_for('download_stats') }}">📥 Descargar stats CSV</a>
    <table><tr><th>Patrón</th><th>Veces bloqueado</th></tr>
      {% for pat,count in stats %}
      <tr><td>{{pat}}</td><td>{{count}}</td></tr>
      {% endfor %}
    </table>
    <a href="{{ url_for('reset_stats') }}">🔄 Reiniciar estadísticas</a>
  {% else %}
    <h1>🔐 Login Administrador</h1>
    <form method="post">
      <input type="text" name="username" placeholder="Usuario" required><br>
      <input type="password" name="password" placeholder="Contraseña" required><br>
      <button type="submit">Entrar</button>
    </form>
  {% endif %}
</body></html>
'''

# ---------------------------
# Rutas auth
# ---------------------------
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        if request.form['username']==ADMIN_USER and request.form['password']==ADMIN_PASS:
            session['logged_in']=True
            flash("✅ ¡Bienvenido, comandante!","warning")
            return redirect(request.args.get('next') or url_for('index'))
        flash("❌ Usuario o contraseña incorrectos.","warning")
    return render_template_string(TEMPLATE,
                                  bloqueos=global_bloqueos,
                                  logs=logs,
                                  stats=sorted(estadisticas.items(), key=lambda x:-x[1]),
                                  maintenance_mode=maintenance_mode)

@app.route('/logout')
@login_required
def logout():
    session.clear(); flash("👋 Hasta luego, alcalde de la DNS.","warning"); return redirect(url_for('login'))

# ---------------------------
# Rutas principales
# ---------------------------
@app.route('/')
@login_required
def index():
    return render_template_string(TEMPLATE,
                                  bloqueos=global_bloqueos,
                                  logs=logs,
                                  stats=sorted(estadisticas.items(), key=lambda x:-x[1]),
                                  maintenance_mode=maintenance_mode)

@app.route('/toggle_maintenance')
@login_required
def toggle_maintenance():
    global maintenance_mode, config
    maintenance_mode = not maintenance_mode
    config['maintenance'] = maintenance_mode
    save_config(config)
    estado = 'activado' if maintenance_mode else 'desactivado'
    flash(f"🔧 Modo mantenimiento {estado}.","warning")
    return redirect(url_for('index'))

@app.route('/add', methods=['POST'])
@login_required
def add_block():
    pat=request.form['pattern'].strip(); ip=request.form['ip'].strip()
    start=request.form.get('start','00:00'); end=request.form.get('end','23:59')
    if not pat.endswith('.'): pat+='.'
    global_bloqueos.append({'pattern':pat,'ip':ip,'start':start,'end':end,'enabled':True})
    config['bloqueos'] = global_bloqueos
    save_config(config)
    flash(f"Añadido: {pat} → {ip} @ {start}-{end}","warning")
    return redirect(url_for('index'))

@app.route('/remove')
@login_required
def remove_block():
    pat=request.args.get('pattern')
    global global_bloqueos, config
    global_bloqueos=[i for i in global_bloqueos if i['pattern']!=pat]
    config['bloqueos'] = global_bloqueos
    save_config(config)
    flash(f"Eliminado: {pat}","warning")
    return redirect(url_for('index'))

@app.route('/toggle')
@login_required
def toggle_rule():
    pat=request.args.get('pattern')
    global config
    for item in global_bloqueos:
        if item['pattern']==pat:
            item['enabled']=not item.get('enabled',True)
            status="habilitada" if item['enabled'] else "deshabilitada"
            flash(f"Regla {status}: {pat}","warning")
            break
    config['bloqueos'] = global_bloqueos
    save_config(config)
    return redirect(url_for('index'))

@app.route('/reset_stats')
@login_required
def reset_stats():
    estadisticas.clear(); flash("🔄 Estadísticas reiniciadas.","warning"); return redirect(url_for('index'))

@app.route('/download_logs')
@login_required
def download_logs():
    si=StringIO(); cw=csv.writerow(si)
    cw.writerow(['ts','client','query','action'])
    for e in logs: cw.writerow([e['ts'],e['client'],e['query'],e['action']])
    return Response(si.getvalue(), mimetype='text/csv', headers={
        'Content-Disposition':'attachment; filename="logs.csv"'
    })

@app.route('/download_stats')
@login_required
def download_stats():
    si=StringIO(); cw=csv.writerow(si)
    cw.writerow(['pattern','count'])
    for pat,count in sorted(estadisticas.items(), key=lambda x:-x[1]): cw.writerow([pat,count])
    return Response(si.getvalue(), mimetype='text/csv', headers={
        'Content-Disposition':'attachment; filename="stats.csv"'
    })

# ---------------------------
# Inicio
# ---------------------------
if __name__=='__main__':
    threading.Thread(target=start_dns, daemon=True).start()
    app.run(host='0.0.0.0',port=4090)
