# Copiloto Cyber

Copiloto de ciberseguridad para gente que programa asistida por IA
("vibecoding") sin mucha experiencia en seguridad. Escanea tu codigo en
busca de los riesgos mas comunes que suelen colarse en codigo generado por
IA, y te avisa en espanol simple antes de que sea un problema.

## Que detecta

- **Secrets hardcodeados**: API keys de AWS/GitHub/Slack/Stripe/Google,
  connection strings con credenciales, bloques de clave privada, JWTs, y
  cualquier valor de alta entropia asignado a una variable con nombre tipo
  `apiKey`/`secret`/`token`/`password`.
- **Patrones de inyeccion**: SQL injection por concatenacion/template
  literals (JS y Python), `eval`/`new Function`, command injection
  (`child_process.exec`, `subprocess` con `shell=True`), XSS via
  `innerHTML`/`dangerouslySetInnerHTML` sin sanitizar.
- **Malas practicas de auth**: CORS abierto a cualquier origen, JWT
  decodificado sin verificar firma, comparacion de contrasenas en texto plano.
- **Dependencias vulnerables**: chequea `package.json` y `requirements.txt`
  contra la base de datos de [OSV.dev](https://osv.dev/) (sin necesidad de API key).

Esto es analisis estatico basado en reglas, no un reemplazo de un pentest ni
de un SAST completo. Prioriza pocos falsos positivos y explicaciones claras
sobre cobertura exhaustiva.

## Uso

```bash
npm install
npm run build

# escanear el directorio actual
node dist/cli/index.js scan .

# escanear una carpeta especifica, sin chequear dependencias (no llama a la red)
node dist/cli/index.js scan ./src --no-deps

# salida en JSON, util para integraciones
node dist/cli/index.js scan . --json

# cambiar el umbral que hace fallar el comando (exit code != 0)
node dist/cli/index.js scan . --fail-on critical
```

Durante desarrollo, `npm run dev -- scan .` corre el CLI directo desde
TypeScript con `tsx`, sin necesidad de build.

### Codigo de salida

El comando devuelve `1` si encuentra hallazgos de severidad igual o mayor a
`--fail-on` (por defecto `high`), lo que lo hace util como pre-commit hook o
como gate de CI.

### Ignorar archivos o carpetas

Crea un archivo `.copilotoignore` en la raiz de lo que estas escaneando,
con un patron por linea (estilo `.gitignore` simplificado: soporta `*` como
wildcard y `**` para cualquier profundidad):

```
fixtures/
*.generated.ts
```

## Reglas

Las reglas de patrones (inyeccion, auth) viven en [`rules/patterns.yaml`](rules/patterns.yaml)
como definiciones declarativas (`id`, `pattern`, `severity`, `description`,
`fixSuggestion`). Se pueden sumar reglas nuevas editando ese archivo, sin
tocar el motor.

## Dogfooding

Este mismo repo corre `copiloto-cyber scan .` sobre si mismo en CI (ver
[`.github/workflows/ci.yml`](.github/workflows/ci.yml)) como gate obligatorio.
La carpeta `test/` esta excluida via `.copilotoignore` porque sus fixtures
contienen secrets y patrones vulnerables *a proposito*, para probar que el
scanner los detecta.

## Desarrollo

```bash
npm test        # corre la suite de Vitest
npm run test:watch
npx tsc --noEmit  # type-check sin emitir
```

## Roadmap (fuera del MVP actual)

- Extension de VS Code / integracion con editores
- GitHub Action reusable para otros repos
- SBOM y chequeo de licencias
- Reglas para mas lenguajes (Go, Ruby, PHP, Java)
- Analisis de riesgo de prompts antes de generar codigo
