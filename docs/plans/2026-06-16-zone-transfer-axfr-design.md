# Diseño: soporte de transferencias de zona (AXFR) — pdns-etcd3 como primario

- **Fecha:** 2026-06-16
- **Rama:** `feat/zone-transfer-axfr`
- **Estado:** diseño (3 decisiones abiertas, ver §10)

## 1. Objetivo y modelo de operación

pdns-etcd3 (vía PowerDNS) debe actuar como **primario authoritative**: un secundario
externo (BIND/NSD/otro PowerDNS) obtiene la zona por **AXFR sobre TCP**, autenticado con
**TSIG**, y es avisado de los cambios mediante **NOTIFY automático** cuando los datos
cambian en etcd.

Decisiones de alcance ya tomadas:

- **Solo AXFR** (transferencia completa). IXFR queda fuera (requeriría journal de deltas).
- **NOTIFY automático** (experiencia de primario real), no solo polling SOA ni NOTIFY manual.
- **TSIG** como mecanismo de seguridad del transfer (firmado criptográfico), con ACL por IP
  como capa adicional opcional.
- **DNSSEC**: se analizan ambos caminos (zona sin firmar y zona *presigned*).

### Reparto de responsabilidades

| Lo hace **PowerDNS** (no se toca) | Lo debe proveer **el backend** (etcd3) |
|---|---|
| Protocolo AXFR/TCP, envoltura SOA al inicio y al final | Lista completa de registros de la zona (`list`) |
| Envío de paquetes NOTIFY a los NS / also-notify | Señalar qué zonas cambiaron (`getUpdatedMasters`) y recordar lo notificado (`setNotified`) |
| Verificación TSIG del request AXFR | Entregar las claves TSIG (`getTSIGKey`) y la ACL (`TSIG-ALLOW-AXFR`) |
| Reintentos, expiry, serial arithmetic (RFC 1982) | Un serial SOA **monótono creciente** y coherente |
| Modo presigned: servir RRSIG tal cual | Almacenar/entregar RRSIG/DNSKEY/NSEC y marcar `PRESIGNED` |

El backend **nunca** habla el protocolo de transferencia: solo responde llamadas JSON-RPC
del remote backend. El alcance se reduce a **añadir métodos al switch de `handleRequest`**
(`src/pdns-etcd3.go:229`) y la lógica de datos detrás.

## 2. Gap analysis — métodos del remote backend

| Método JSON-RPC (lowercased) | Para qué | Estado en `master` | Acción |
|---|---|---|---|
| `lookup` | resolución normal | OK `lookup()` | — |
| `getalldomains` | enumerar zonas | Parcial: `allDomains()` devuelve solo `{zone,serial}` (`src/data.go`) | Añadir `kind:"MASTER"` + `id` |
| `getdomaininfo` | info de 1 zona | Parcial: devuelve `{zone,serial}` (`src/metadata.go:40`) | Añadir `kind`, `id`, `notified_serial` |
| `getdomainmetadata` | ALLOW-AXFR-FROM, PRESIGNED, ALSO-NOTIFY… | OK passthrough genérico (`src/metadata.go:54`) | Funciona — solo poblar etcd |
| `setdomainmetadata` | — | OK transaccional (`src/metadata.go:72`) | — |
| **`list`** | **AXFR-OUT** | **No existe** | Implementar + zone-walk |
| **`getupdatedmasters` / `getupdatedprimaries`** | detectar cambios → NOTIFY | No existe | Implementar |
| **`setnotified`** | recordar serial notificado | No existe | Implementar (reusar `src/transaction.go`) |
| **`gettsigkey` / `gettsigkeys`** | claves TSIG | No existe | Implementar + almacén en etcd |

**Compatibilidad de versiones:** PowerDNS renombró `master/slave` → `primary/secondary`
en 4.5. El nombre JSON que llega puede ser `getUpdatedMasters` **o** `getUpdatedPrimaries`,
y `kind` puede esperarse `"MASTER"` o `"PRIMARY"` según versión. El repo prueba una matriz
PDNS 3.4→5.1, así que el switch debe atender **ambos** nombres.

## 3. Requisitos funcionales

### R1 — Método `list` + enumeración de zona (núcleo del AXFR)

PDNS envía `{"method":"list","parameters":{"zonename":"...","domain_id":N}}` y espera
**todos** los registros de la zona (mismo formato que `lookup`:
`qname,qtype,ttl,content,auth,domain_id`). Hoy **no existe función de zone-walk**: `lookup`
solo accede a un nodo (`src/lookup.go:74`). Hay que construir un recorrido recursivo del
subárbol de la zona (`data.children`) que **se detenga al cruzar a una zona hija**
(`hasSOA()`, `src/data.go:135`), emitiendo cada `records[qtype][id]` vía `makeResultItem`,
**incluyendo SOA y NS de delegación**.

### R2 — Identidad de zona (`domain_id`)

`setNotified` entrega **solo** un `id` entero; `getDomainInfo`/`getAllDomains`/`list` también
lo manejan. Hoy las zonas se identifican por **nombre**, no hay enteros. Se necesita un
**mapa estable id↔zona**. Recomendación: registro en memoria que asigna ids secuenciales por
orden determinista al cargar; el `notified_serial` se persiste **por nombre** en etcd (no por
id), así la estabilidad del id entre reinicios no afecta a la corrección.

### R3 — `getDomainInfo` y `getAllDomains` con metadatos de primario

Ambos deben reportar `kind` = `MASTER`/`PRIMARY`, el `id` (R2) y, en `getDomainInfo`, el
`notified_serial` (R4). Sin `kind=MASTER`, el hilo primario de PDNS no considera la zona para
NOTIFY.

### R4 — NOTIFY automático (`getUpdatedMasters`/`getUpdatedPrimaries` + `setNotified`)

- `getUpdatedMasters`: recorrer zonas, comparar `soaSerial(zona)` con el `notified_serial`
  almacenado, devolver **solo las que difieren** con `{id,zone,serial,notified_serial,kind}`.
- `setNotified(id,serial)`: resolver id→zona (R2) y guardar el serial notificado
  **en memoria** (en el registro de zonas), **no** en etcd. Refinamiento descubierto al
  planificar: persistir `notified_serial` bajo el prefijo de la zona subiría `maxRev` →
  subiría el serial → la zona volvería a aparecer "cambiada" → **bucle de NOTIFY infinito**.
  El estado in-memory es correcto (solo refleja "lo ya notificado"); perderlo al reiniciar
  solo provoca un re-NOTIFY inocuo. Consecuencia: **la operación primaria/NOTIFY requiere
  modo standalone** (proceso longevo). Ver el plan de implementación, fase F2.
- Destinatarios del NOTIFY: PDNS notifica a los **NS de la zona** (resueltos) + `ALSO-NOTIFY`
  (metadata, ya funciona por passthrough). Requiere `primary=yes` en la config de PDNS.

### R5 — Serial SOA monótono (riesgo crítico para transferencias)

El serial se deriva de `zoneRev()` = revisión etcd máxima de la zona, y se imprime tal cual
con `%d` en el contenido SOA (`src/rr.go:350`, `soaSerial()` en `src/rr.go:271`). Riesgos
para un secundario que compara seriales:

- *Salto hacia atrás al borrar claves* — ya mitigado con `X-PE3-MINIMUM-SERIAL`
  (`handleEvents`, `src/pdns-etcd3.go`).
- *Overflow uint32*: la revisión de etcd es `int64` y crece globalmente; el serial SOA en
  cable es `uint32`. En clústeres longevos/ocupados puede superar 2^32. RFC 1982 tolera
  wraparound, pero la **conversión int64→uint32** debe ser explícita y monótona para no
  romper la comparación en el borde.
- `X-PE3-FIXED-SERIAL` (`src/rr.go:271`) permite fijar el serial manualmente.

Para un primario AXFR dinámico hace falta **garantía explícita de monotonicidad** del valor
uint32 servido (ver decisión §10.2).

### R6 — Seguridad TSIG

- Implementar `getTSIGKey`/`getTSIGKeys`: PDNS pide `{name}` y espera
  `{name, algorithm, content(base64)}`. Hay que **almacenar claves TSIG en etcd** (esquema
  nuevo) y devolverlas.
- ACL: metadata `TSIG-ALLOW-AXFR` (lista de nombres de clave permitidos por zona) — **ya sale
  por el passthrough** de `getDomainMetadata`; solo hay que poblarla.
- Recomendado además: `allow-axfr-ips` / `ALLOW-AXFR-FROM` como segunda capa (coste casi nulo).

### R7 — DNSSEC sobre AXFR (ambos caminos)

- **Camino A — zona sin firmar:** `list` emite los registros tal cual. Sin requisitos extra
  más allá de R1–R6. Es el MVP del transfer.
- **Camino B — presigned (rama ya fusionada en master):** DNSKEY/RRSIG/NSEC/NSEC3 se guardan
  como *plain strings* y se sirven verbatim (caen al passthrough, no están en `rrFuncs`). Para
  AXFR presigned correcto hacen falta además:
  1. Metadata `PRESIGNED=1` por zona, para que PDNS **no re-firme** y transmita los RRSIG
     almacenados.
  2. **Serial coherente con `RRSIG(SOA)`**: usar `X-PE3-FIXED-SERIAL` para que el serial
     servido == el firmado. Implica que, al cambiar datos, el operador debe re-firmar **y**
     subir el serial fijo (limitación inherente al presigned).
  3. **Flags `auth` correctos** en `list`: NS de delegación y glue deben ir `auth=0`; el resto
     `auth=1`. Hoy el backend no calcula `auth` (R1 debe añadirlo).
  4. **Cadena NSEC/NSEC3 completa** presente como datos (incluidos los ENT). En presigned es
     responsabilidad de quien firma/puebla etcd, no del backend.

## 4. Concurrencia: snapshot consistente de la zona

Un AXFR enumera **toda** la zona mientras `handleEvents` (`src/pdns-etcd3.go:254`) puede estar
recargándola. Convenciones a respetar (`CLAUDE.md` / `src/data.go`):

- `list` debe tomar el árbol vía `getChild(name,true)` y `rUnlockUpwards` diferido (patrón de
  `withRLock`, `src/metadata.go:25`).
- Decisión abierta (§10.1): RLock de toda la zona durante toda la transferencia (consistencia
  fuerte, posible contención con writers) **vs** snapshot/copia de los registros bajo lock y
  soltar antes de serializar (menos contención, más memoria).

## 5. Modelo de datos en etcd y versionado

Claves nuevas a introducir:

- `…/-metadata-/X-PE3-NOTIFIED-SERIAL` (por zona) — serial notificado (R4).
- Almacén de claves **TSIG** (R6) — definir ubicación/esquema (ver §10.3).
- Metadata existente reutilizable por passthrough: `PRESIGNED`, `TSIG-ALLOW-AXFR`,
  `ALSO-NOTIFY`, `ALLOW-AXFR-FROM`.

Cualquier cambio de forma on-etcd implica **bump de `dataVersion`** en `src/data.go` y
actualizar `doc/ETCD-structure.md` (regla de `CLAUDE.md`).

## 6. Configuración PowerDNS requerida

`primary=yes` (o `master=yes` < 4.5); NOTIFY a NS + `also-notify`; `allow-axfr-ips`/TSIG; el
connector remote en modo apropiado (pipe/unix con `initialize`, o `http` con `-pdns-version`).
En modo HTTP no hay `initialize`, así que la versión de PDNS para decidir nombres
`master`↔`primary` viene del flag `-pdns-version`.

## 7. Fuera de alcance (fases posteriores)

- **IXFR**: requeriría journal de deltas versionado en etcd.
- **AXFR-IN / ser secundario** (`startTransaction`/`feedRecord`/`commitTransaction`): no aplica.
- **Live-signing DNSSEC** (`getDomainKeys`/`addDomainKey`…): el modelo es presigned.

## 8. Testing

- **Unit**: zone-walk de `list` (incluye SOA/NS/glue, se detiene en zona hija, flags `auth`);
  comparación serial vs notified en `getUpdatedMasters`; resolución id↔zona; `getTSIGKey`.
- **Integración** (testcontainers, patrón de `src/integration_test.go`): levantar pdns-etcd3
  como primario + un **secundario real** (PowerDNS o NSD/BIND en contenedor) y verificar
  (a) AXFR transfiere la zona, (b) NOTIFY dispara refresh tras cambiar etcd, (c) TSIG rechaza
  sin clave / acepta con clave, (d) variante presigned valida la zona firmada. Resolver con
  `miekg/dns` (ya en uso).

## 9. Fases de implementación

| Fase | Contenido | Tamaño |
|---|---|---|
| **F1 — AXFR básico** | R1 (`list`+zone-walk), R2 (id), R3 (kind/id) | Mediano |
| **F2 — NOTIFY automático** | R4 (`getUpdatedMasters`/`setNotified`, persistencia) | Mediano |
| **F3 — TSIG** | R6 (`getTSIGKey` + almacén etcd + ACL) | Mediano |
| **F4 — DNSSEC presigned sobre AXFR** | R7-B (auth flags, PRESIGNED, serial coherente) | Pequeño-Mediano |
| **transversal** | R5 (monotonicidad serial), versionado + docs, tests integración | Mediano |

## 10. Decisiones de diseño (resueltas — 2026-06-16)

1. **Estrategia de snapshot del AXFR** (§4) → **RLock del subárbol durante el walk.**
   `list` es una única petición/respuesta JSON: el backend materializa el array completo de
   registros en memoria y responde; el transfer TCP al secundario lo hace PowerDNS *después*,
   sin lock del backend. Por tanto el RLock solo se sostiene durante el recorrido en memoria
   (rápido), con consistencia fuerte y contención despreciable. Trabajo: recorrido recursivo
   que RLockea/RUnlockea cada hijo y se detiene en zonas hijas (`hasSOA()`).

2. **Serial uint32 monótono** (§R5) → **proyección uint32 de `zoneRev()`.**
   Emitir `uint32(zoneRev())` manteniendo el suelo `X-PE3-MINIMUM-SERIAL` en espacio `int64`.
   Es monótono bajo RFC 1982 porque los incrementos entre sondeos del secundario son ≪ 2^31,
   así el wraparound se interpreta correctamente como "más nuevo". Conserva el serial
   automático cero-mantenimiento. Precedencia de serial: `X-PE3-FIXED-SERIAL` (presigned) >
   suelo `X-PE3-MINIMUM-SERIAL` > proyección automática.

3. **Almacén de claves TSIG** (§R6) → **global por nombre bajo pseudo-prefijo `-tsig-/<nombre>`.**
   Las claves TSIG son objetos globales referenciados por nombre (`getTSIGKey(name)` no recibe
   zona). Se guardan como objeto `{algorithm, secret}` (JSON5/YAML), análogo a los pseudo-
   entries `-metadata-`/`-lock-` (`src/const.go:52`). La ACL "qué clave transfiere qué zona"
   la sigue dando la metadata `TSIG-ALLOW-AXFR` por zona (passthrough existente). Nota de
   seguridad: el secreto vive en etcd → proteger con ACLs/cifrado en reposo y documentarlo.
