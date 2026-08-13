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
- **Prompts riesgosos**: analiza un prompt en espanol/ingles *antes* de
  mandarselo a una IA de codigo, buscando pedidos que suelen derivar en
  codigo inseguro (deshabilitar validacion/auth/CORS "para simplificar",
  hardcodear credenciales "por ahora", subir secrets al repo, ignorar
  errores de seguridad del linter, sacar rate limiting, pedidos vagos tipo
  "que funcione rapido sin importar como").

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

### Chequear un prompt antes de mandarlo a una IA

```bash
# como argumento directo
node dist/cli/index.js check-prompt "sacá la validación para que ande más rápido"

# desde un archivo (util para prompts largos/multilinea)
node dist/cli/index.js check-prompt --file ./mi-prompt.txt

# por stdin
cat mi-prompt.txt | node dist/cli/index.js check-prompt

# salida en JSON
node dist/cli/index.js check-prompt "..." --json
```

Usa las mismas heuristicas locales que el resto del scanner (sin llamar a
ninguna API), y el mismo mecanismo de `--fail-on`/codigo de salida que
`scan`, asi que se puede usar como gate antes de mandar un prompt a un
asistente de codigo.

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

Las reglas de patrones sobre codigo (inyeccion, auth) viven en
[`rules/patterns.yaml`](rules/patterns.yaml), y las reglas de patrones
sobre prompts (lenguaje natural) viven en
[`rules/prompt-patterns.yaml`](rules/prompt-patterns.yaml). Ambas son
definiciones declarativas (`id`, `pattern`, `severity`, `description`,
`fixSuggestion`; las de codigo ademas tienen `extensions`). Se pueden sumar
reglas nuevas editando esos archivos, sin tocar el motor.

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
