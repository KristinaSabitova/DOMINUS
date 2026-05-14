# DOMINI Suite — Informe Técnico
## Framework de Reconocimiento OSINT Pasivo para Dominios e IPs

---

## Visión general

La DOMINI Suite es un framework de reconocimiento OSINT pasivo compuesto por dos herramientas complementarias:

- **DOMINUS** — Inteligencia de Dominios y Puntuación de Riesgo
- **SENTINEL** — Análisis de Reputación de IPs e Inteligencia de Amenazas

Ambas herramientas operan exclusivamente sobre información disponible públicamente. Ninguna explota vulnerabilidades, accede a sistemas restringidos ni genera ruido de red detectable como ataque. Están diseñadas para replicar la fase de reconocimiento que realizaría un analista de seguridad profesional — o un atacante hábil — antes de cualquier engagement.

La suite fue construida como alternativa directa a las herramientas OSINT centradas en personas (Sherlock, Holehe, Maigret). En lugar de perfilar individuos, perfila **infraestructura**: dominios, servidores, configuraciones y reputación de IPs.

---

## Filosofía de arquitectura

Ambas herramientas comparten un patrón arquitectónico idéntico:

```
Objetivo (dominio o IP)
    │
    ├── Fase 1: Módulo A  →  run(objetivo) → dict
    ├── Fase 2: Módulo B  →  run(objetivo) → dict
    ├── Fase N: Módulo N  →  run(objetivo) → dict
    │
    ├── Engine: orquesta fases, captura errores por fase
    ├── Scorer: calcula puntuación de riesgo/amenaza ponderada
    └── Generator: produce informe HTML standalone
```

**Decisiones de diseño clave:**

**Contrato uniforme.** Cada módulo expone una única función `run(objetivo) -> dict`. Añadir una nueva fuente de inteligencia requiere solo crear un nuevo archivo de módulo y registrarlo en `engine.py`. Sin cambios en el código existente.

**Aislamiento de fallos.** El engine envuelve cada fase en un try/except. Si una fase falla (timeout de API, error de red, problema de parsing), el resto continúa sin verse afectado. Las fases fallidas quedan marcadas en el informe, no ignoradas silenciosamente.

**Puntuación transparente.** El Risk/Threat Score se calcula con pesos declarativos. Cada punto añadido al score va acompañado de una razón legible por humanos almacenada en los resultados. El informe nunca muestra un número sin explicarlo.

**Informes sin dependencias.** El output HTML tiene todo CSS y JS inline. Los únicos recursos externos son Google Fonts y Leaflet.js (SENTINEL), ambos cargados desde CDN. Un informe generado hoy puede abrirse en cinco años sin assets rotos.

---

## DOMINUS — Inteligencia de Dominios

### Qué hace

DOMINUS realiza un reconocimiento pasivo de seis fases sobre un dominio, agregando toda la información públicamente disponible sobre su configuración, infraestructura y exposición.

### Desglose de fases

**WHOIS**
Consulta el registro WHOIS del dominio para obtener registrador, organización del titular, fechas de creación y expiración, servidores de nombres y flags de estado. Detecta servicios de protección de privacidad (WhoisGuard, Domains by Proxy, etc.) que ocultan la identidad del titular. Calcula la antigüedad del dominio y los días hasta la expiración — un dominio que expira pronto es un indicador de riesgo.

**DNS**
Resuelve todos los tipos principales de registros DNS (A, AAAA, MX, NS, TXT) y realiza análisis profundo de los registros de autenticación de email:
- **SPF** (Sender Policy Framework): detecta si la política usa hard-fail (`-all`), soft-fail (`~all`) o está ausente. El soft-fail significa que remitentes no autorizados aún pueden entregar emails que pasan comprobaciones básicas.
- **DMARC**: detecta la política de aplicación (`p=none`, `p=quarantine`, `p=reject`). Un dominio con `p=none` puede ser suplantado libremente para phishing — emails de `ceo@objetivo.com` pueden llegar a bandejas de entrada sin ningún fallo de autenticación.
- **DKIM**: intenta detectar selectores DKIM comunes para confirmar si la firma está configurada.

**Subdominios**
Consulta los logs de Certificate Transparency via la API pública de crt.sh. Cada certificado TLS emitido para un dominio queda registrado públicamente — esto revela subdominios sin enviar un solo paquete al objetivo. Hallazgos comunes: `dev.`, `staging.`, `admin.`, `api.`, `vpn.` — subdominios que frecuentemente tienen seguridad más débil que producción.

**Puertos**
Ejecuta un escaneo nmap contra las IPs resueltas del dominio. Comprueba una lista curada de puertos de alto riesgo: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 80/443 (HTTP/S), 110/143 (POP/IMAP), 445 (SMB), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 6379 (Redis), 8080/8443 (HTTP alternativo). Cada puerto abierto se puntúa por nivel de riesgo.

**Cabeceras**
Realiza una petición HTTPS al dominio y audita las cabeceras de seguridad en la respuesta:
- `Content-Security-Policy` — previene XSS poniendo en lista blanca orígenes de scripts/estilos
- `Strict-Transport-Security` — impone HTTPS y previene SSL stripping
- `X-Frame-Options` — previene clickjacking
- `X-Content-Type-Options` — previene MIME sniffing
- `Referrer-Policy` — controla la filtración de URLs a terceros
- `Permissions-Policy` — restringe el acceso a funciones del navegador (cámara, geolocalización, etc.)
- Cabecera `Server` — la exposición de la tecnología del servidor (Apache, nginx, wetopi, etc.) facilita el fingerprinting

**LeakRadar**
Busca filtraciones de credenciales públicas asociadas al dominio. Opera en dos modos:
- *Modo A (API):* Consulta la base de datos de threat intelligence de LeakRadar (5.000M+ credenciales) si hay una API key configurada. Devuelve total de filtraciones, desglose por categoría y emails de muestra.
- *Modo B (fallback):* Cuando no hay API key, ejecuta Google Dorks contra Pastebin (`site:pastebin.com "dominio.com" password`, etc.) para localizar dumps de credenciales indexados públicamente. Esta es exactamente la técnica que usan los atacantes en la fase de reconocimiento.

### Cálculo del Risk Score

| Fase | Peso máximo | Señales de riesgo clave |
|------|------------|------------------------|
| WHOIS | 10 | Dominio próximo a expirar, sin info del titular |
| DNS | 15 | DMARC p=none (+8), SPF soft-fail (+4), sin SPF (+7) |
| Subdominios | 20 | Subdominios admin/dev/staging encontrados |
| Puertos | 35 | RDP abierto (+20), puertos de base de datos (+15), SSH abierto (+5) |
| Cabeceras | 20 | Sin CSP (+8), sin HSTS (+5), banner de servidor (+3) |

Total máximo: 100. La puntuación refleja la explotabilidad real, no el cumplimiento teórico.

---

## SENTINEL — Inteligencia de Amenazas de IPs

### Qué hace

SENTINEL realiza un análisis de inteligencia de amenazas de seis fases sobre una dirección IP, combinando geolocalización, historial de abuso, feeds de amenazas activas, escaneo de puertos, detección de proveedor cloud y verificación en tiempo real de nodos Tor.

### Desglose de fases

**Geolocalización**
Consulta ip-api.com (sin API key) para resolver la IP a país, ciudad, región, coordenadas, ASN (Número de Sistema Autónomo), ISP y nombre de organización. El ASN es especialmente valioso — identifica inmediatamente si la IP pertenece a una empresa legítima, un proveedor de hosting, un host bulletproof conocido o un ISP residencial.

**Abuso**
Consulta la base de datos AbuseIPDB para el historial de reportes de la IP:
- Total de reportes únicos
- Abuse confidence score (0–100, calculado por AbuseIPDB a partir de la calidad y consistencia de los reportes)
- Categorías de ataque: SSH brute force, port scanning, ataque web, DDoS, spam, phishing, SQL injection, etc.
- Fecha del reporte más reciente

Un confidence score superior al 80% con 50+ reportes es un fuerte indicador de host malicioso o comprometido.

**Feeds de Amenazas**
Consulta AlienVault OTX (Open Threat Exchange), la mayor comunidad abierta de inteligencia de amenazas del mundo:
- Número de pulsos de amenaza en los que aparece la IP
- Tipos de indicadores asociados (C2 de malware, escáner, brute forcer, etc.)
- Asociaciones con actores de amenaza o campañas cuando están disponibles

**Puertos**
El mismo escaneo basado en nmap que DOMINUS. Para análisis a nivel de IP, los puertos abiertos proporcionan contexto adicional: una IP residencial con el puerto 22 abierto puede indicar un host comprometido siendo usado como proxy.

**Detección Cloud**
Descarga y analiza los archivos de rangos de IPs públicos oficiales de AWS, Azure, GCP y Cloudflare. Determina si la IP pertenece a un proveedor cloud importante y qué servicio/región específico. Este contexto importa: un ataque desde una IP de AWS puede indicar una instancia EC2 comprometida o un atacante abusando de infraestructura cloud para el anonimato.

**Detección Tor**
Obtiene la lista de nodos de salida Tor en tiempo real desde dan.me.uk/torlist. Si la IP está en la lista, es un nodo de salida Tor activo en el momento del escaneo. Este es un hallazgo crítico: los nodos de salida Tor acumulan reportes de abuso de todos los usuarios que los atraviesan, y bloquear un único nodo de salida ofrece protección mínima ya que el atacante puede cambiar instantáneamente a otro.

### Cálculo del Threat Score

| Fase | Peso máximo | Señales de riesgo clave |
|------|------------|------------------------|
| Geolocalización | 15 | País de alto riesgo, ASN de hosting bulletproof |
| Abuso | 30 | Alto confidence score, muchos reportes, categorías severas |
| Feeds de Amenazas | 25 | Múltiples pulsos OTX, asociación con C2 de malware |
| Puertos | 20 | Puertos sensibles abiertos en IP no-servidor |
| Cloud | -10 | Proveedor cloud legítimo reduce la puntuación |
| Tor | +30 | Nodo de salida Tor activo (bonus fijo) |

---

## Flujo de trabajo combinado: DOMINUS + SENTINEL

Las dos herramientas están diseñadas para usarse secuencialmente. DOMINUS descubre infraestructura; SENTINEL la perfila.

```
DOMINUS(dominio)
    └── Fase DNS → registros A → IPs
                              └── SENTINEL(IP) × n
                                      └── Perfil de amenaza completo por IP
```

**Qué aprendes de cada herramienta:**

| Pregunta | Herramienta |
|----------|-------------|
| ¿Puede este dominio usarse para phishing/suplantación? | DOMINUS (DMARC/SPF) |
| ¿Hay paneles de administración o entornos dev expuestos? | DOMINUS (subdominios) |
| ¿Se han filtrado credenciales de empleados públicamente? | DOMINUS (LeakRadar) |
| ¿Está el servidor ejecutando software desactualizado? | DOMINUS (cabeceras/puertos) |
| ¿Está esta IP asociada con ataques conocidos? | SENTINEL (abuso/OTX) |
| ¿Es esta IP un nodo Tor o VPN? | SENTINEL (detección Tor) |
| ¿Dónde está físicamente esta IP y quién la posee? | SENTINEL (geolocalización) |
| ¿Viene este ataque de infraestructura cloud? | SENTINEL (detección cloud) |

**Conclusión combinada de un ejemplo (ejemplo.es):**

DOMINUS revela: DMARC p=none (suplantación posible), SPF soft-fail, banner de servidor (wetopi) expuesto, sin cabecera CSP. Risk Score: 14/100 BAJO.

SENTINEL revela (ambas IPs): Hosting OVH/Wetopi, España + Países Bajos, Threat Score 2/100 BAJO, sin historial de abuso, sin Tor, sin flags de proveedor cloud.

**Evaluación final:** La infraestructura del dominio es limpia y bien alojada. El riesgo está completamente en la configuración DNS/email — una campaña de phishing dirigida suplantando las direcciones de email de este dominio probablemente tendría éxito porque DMARC no impone el rechazo. La superficie de ataque es estrecha pero real.

---

## Aplicaciones prácticas

### Para profesionales de seguridad
- Reconocimiento previo al engagement en tests de penetración autorizados
- Evaluación de la superficie de ataque externa para clientes
- Enriquecimiento de inteligencia de amenazas para alertas SOC
- Evaluación de la postura de seguridad de proveedores

### Para desarrolladores y administradores de sistemas
- Auto-evaluación de la propia infraestructura
- Detectar DNS mal configurado antes de que lo hagan los atacantes
- Verificar que las cabeceras de seguridad están correctamente configuradas
- Monitorizar filtraciones de credenciales del propio dominio

### Para uso académico e investigación
- Demostrar técnicas OSINT de forma controlada y legal
- Entender qué revela la información pública sobre la postura de seguridad
- Aprender flujos de trabajo de inteligencia de amenazas usados en entornos profesionales

---

## Qué NO hace la DOMINI Suite

- No explota ninguna vulnerabilidad
- No accede a ningún sistema sin autorización
- No realiza fuerza bruta ni escaneo agresivo
- No almacena, comparte ni transmite ningún dato recopilado
- No interactúa con ningún sistema más allá de leer respuestas disponibles públicamente

Todos los datos recopilados por ambas herramientas ya son públicos. La suite automatiza lo que un analista humano haría manualmente usando whois.domaintools.com, mxtoolbox.com, shodan.io, abuseipdb.com y búsqueda en Google.


<img width="1903" height="2778" alt="DOMINUS — " src="https://github.com/user-attachments/assets/79ffe2e5-ca3d-4b75-ac0c-1671319352c7" />


<img width="1510" height="2585" alt="sentinel" src="https://github.com/user-attachments/assets/6eddfc1d-fc7a-425c-8bdc-76f388e0b74e" />

---

## Aviso legal

La DOMINI Suite está destinada a evaluaciones de seguridad autorizadas, investigación académica y auto-evaluación de infraestructura que posees o tienes permiso explícito para analizar. El reconocimiento no autorizado de sistemas de terceros puede violar las leyes de fraude informático en tu jurisdicción.

---

## Sobre el proyecto

Desarrollado como proyecto académico de ciberseguridad en **Evolve Academy**.

**DOMINUS** → [github.com/youruser/dominus](https://github.com/youruser/dominus)  
**SENTINEL** → [github.com/youruser/sentinel](https://github.com/youruser/sentinel)

---

*DOMINI Suite — inteligencia pasiva, visión activa.*
