# DNServer

DNServer es una herramienta de bloqueo y redirección DNS, desarrollada en Python con Flask y dnslib, que permite gestionar reglas de filtrado, visualización de estadísticas y administración desde una interfaz web.

## Características

* **Bloqueo DNS**: Gestión de respuestas REFUSED o redirección a una dirección IP especificada.
* **Wildcards**: Soporte de patrones con comodines (`*.ejemplo.com.`) para abarcar múltiples subdominios.
* **Horario de bloqueo**: Configuración de franjas horarias diarias para activar o desactivar reglas de bloqueo.
* **Habilitar/deshabilitar reglas**: Mantener reglas inactivas sin eliminarlas permanentemente.
* **Modo mantenimiento**: Responde con un registro TXT personalizado para todas las consultas DNS.
* **Interfaz web (Dashboard)**:

  * Gestión de reglas de bloqueo.
  * Visualización de logs en tiempo real.
  * Estadísticas de bloqueos por patrón.
  * Exportación de logs y estadísticas en CSV.
* **Autenticación básica**: Acceso protegido mediante usuario y contraseña.
* **Persistencia**: Configuración y estado guardados en un archivo JSON (`config.json`).

## Requisitos

* Python 3.7 o superior
* Paquetes Python:

  ```bash
  pip install flask dnslib
  ```
* Permisos de root para escuchar en el puerto 53 (UDP).

## Estructura de archivos

```text
├── dnsblock.py      # Código principal de la aplicación
├── config.json      # Archivo de configuración y reglas (generado automáticamente)
├── logs.csv         # Exportación de logs (opcional, en tiempo de ejecución)
└── stats.csv        # Exportación de estadísticas (opcional, en tiempo de ejecución)
```

## Configuración

Al ejecutarse por primera vez, se genera `config.json` con la siguiente estructura:

```json
{
  "bloqueos": [],
  "maintenance": false
}
```

* **`bloqueos`**: Lista de objetos con las reglas de bloqueo:

  * `pattern` (string): Patrón de dominio (con wildcard).
  * `ip` (string): Dirección IP de redirección o `REFUSED`.
  * `start` (string, formato `HH:MM`): Hora de inicio de bloqueo.
  * `end` (string, formato `HH:MM`): Hora de fin de bloqueo.
  * `enabled` (boolean): Estado de la regla.
* **`maintenance`**: Indica si el modo mantenimiento está activo (`true` o `false`).

### Credenciales por defecto

* **Usuario**: `admin`
* **Contraseña**: `admin`

> Se recomienda modificar las credenciales antes de poner en producción.

## Instalación y ejecución

1. Clona el repositorio o copia `dnsblock.py` al servidor.
2. Instala los requisitos:

   ```bash
   pip install flask dnslib
   ```
3. (Opcional) Configura el firewall para permitir tráfico DNS en el puerto 53 (UDP).
4. Ejecuta la aplicación como root si deseas usar el puerto 53:

   ```bash
   sudo python3 dnsblock.py
   ```
5. Accede al Dashboard en `http://<IP_SERVIDOR>:4090`.

## Uso

Inicia sesión con las credenciales definidas y utiliza la interfaz para:

* **Activar/Desactivar modo mantenimiento**.
* **Agregar nuevas reglas**: Dominio, IP/REFUSED y horario.
* **Habilitar/Deshabilitar reglas** existentes.
* **Eliminar reglas**.
* **Visualizar logs** y exportarlos en CSV.
* **Consultar estadísticas** de bloqueos y exportarlas.
* **Reiniciar estadísticas**.

### Rutas principales (Flask)

| Ruta                  | Método   | Descripción                                 |
| --------------------- | -------- | ------------------------------------------- |
| `/`                   | GET      | Dashboard principal (requerido login).      |
| `/login`              | GET/POST | Autenticación de usuario.                   |
| `/logout`             | GET      | Cierra la sesión.                           |
| `/toggle_maintenance` | GET      | Activa/desactiva modo mantenimiento.        |
| `/add`                | POST     | Añade una nueva regla de bloqueo.           |
| `/remove?pattern=...` | GET      | Elimina la regla especificada.              |
| `/toggle?pattern=...` | GET      | Habilita/deshabilita la regla especificada. |
| `/reset_stats`        | GET      | Reinicia las estadísticas de bloqueo.       |
| `/download_logs`      | GET      | Descarga los logs en formato CSV.           |
| `/download_stats`     | GET      | Descarga las estadísticas en formato CSV.   |

## Contribuciones

Las contribuciones son bienvenidas. Para aportar mejoras o correcciones:

1. Abre un *issue* describiendo el problema o la propuesta.
2. Realiza un *fork* del repositorio.
3. Crea una *branch* con tus cambios.
4. Envía un Pull Request con la descripción de tus cambios.

## Licencia

Este proyecto está bajo la **Licencia GNU GPLv3**. Por favor, consulte el archivo [LICENSE](LICENSE) para más detalles.
