# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Sobre o repositório

Fork do `libsignal-node` (implementação do Signal Protocol para Node.js, originalmente de ForstaLabs / Open Whisper Systems). O propósito deste fork, conforme o nome sugere, é remover logs ruidosos do código upstream. É consumido principalmente por projetos WhatsApp (Baileys-like).

Publicado como pacote `libsignal` (campo `main`: `index.js`). Sem suíte de testes, sem script de build de JS — apenas regeneração de protobufs.

## Comandos

- Instalar deps: `yarn install`
- Regenerar `src/WhisperTextProtocol.js` a partir do `.proto`: `./generate-proto.sh`
  (executa `yarn pbjs -t static-module -w commonjs` — só rode se `protos/WhisperTextProtocol.proto` mudar; o arquivo gerado é commitado)
- Lint: `npx eslint src/` (eslint 6 está em devDependencies, mas não há config dedicada no repo — verificar antes de assumir regras)

## Arquitetura

`index.js` é o único ponto de entrada e apenas reexporta módulos de `src/`. Toda a API pública está ali.

Fluxo conceitual do Signal Protocol implementado aqui:

1. **`keyhelper.js` + `curve.js`** — geração de chaves (identity, prekeys, signed prekeys) usando `curve25519-js`. `curve.js` encapsula sign/verify/DH (X25519/Ed25519) e detalhes do formato de chave pública do Signal (prefixo `0x05` `DJB_TYPE`).
2. **`crypto.js`** — primitivas de baixo nível: AES-CBC, HMAC-SHA256, HKDF. Usadas em todo o ratchet.
3. **`session_builder.js`** — estabelece sessões (Double Ratchet handshake). Dois caminhos:
   - `initOutgoing(device)`: parte de um PreKeyBundle do destinatário.
   - `initIncoming(record, message)`: processa um `PreKeySignalMessage` recebido.
   Toda mutação de `SessionRecord` passa por `queueJob(fqAddr, …)` para serializar operações por endereço.
4. **`session_cipher.js`** — `encrypt` / `decryptWhisperMessage` / `decryptPreKeyWhisperMessage`. Avança o ratchet, gerencia chains/message keys, lida com mensagens fora de ordem (cache de message keys saltadas). Também serializa por `queueJob` no mesmo `fqAddr`.
5. **`session_record.js`** — estrutura serializável de estado. Um `SessionRecord` contém múltiplos `SessionEntry` (um por baseKey); o entry "open" é o ativo. Mantém histórico de sessões fechadas até `CLOSED_SESSIONS_MAX = 40`. `SESSION_RECORD_VERSION = 'v1'`. Buffers são serializados como base64 nos JSONs internos.
6. **`protocol_address.js`** — par `(id, deviceId)` com `toString()` `"id.deviceId"`. É a chave usada em todo lugar (storage, queueJob).
7. **`queue_job.js`** — fila de promessas por chave; garante que operações concorrentes sobre o mesmo `fqAddr` sejam serializadas. Crucial: tanto `SessionBuilder` quanto `SessionCipher` usam a mesma fila com a mesma chave para evitar corridas no `SessionRecord`.
8. **`protobufs.js` → `WhisperTextProtocol.js`** — wire format (`WhisperMessage`, `PreKeyWhisperMessage`). `WhisperTextProtocol.js` é **gerado** por `protobufjs` (`pbjs`); não edite à mão.
9. **`errors.js`** — `UntrustedIdentityKeyError`, `SessionError`, `MessageCounterError`, `PreKeyError`. Reexportados via `Object.assign(exports, require('./src/errors'))` em `index.js`.

## Contrato do `storage`

Várias APIs (`SessionBuilder`, `SessionCipher`) recebem um objeto `storage` injetado pelo consumidor. Métodos esperados (verificar usos em `session_builder.js` / `session_cipher.js` antes de mudar assinatura): `isTrustedIdentity`, `loadPreKey`, `removePreKey`, `loadSignedPreKey`, `loadSession`, `storeSession`, `getOurIdentity`, `getOurRegistrationId`, `saveIdentity`. Este repo não fornece implementação — é responsabilidade do consumidor.

## Convenções importantes

- Buffers são obrigatórios em quase toda API que toca bytes — há `assertBuffer` em `session_record.js` e `session_cipher.js`. Não passe `Uint8Array` puro.
- Chaves públicas do Signal têm 33 bytes (prefixo `0x05`). `curve.js` aceita ambos os formatos em algumas funções e normaliza — atenção ao adicionar novas.
- `VERSION = 3` em `session_cipher.js` é a versão do wire format de mensagem; não mexer sem motivo.
- Operações que alteram `SessionRecord` **devem** rodar dentro de `queueJob(this.addr.toString(), …)` para manter atomicidade.
- O upstream original deste fork é `ForstaLabs/libsignal-node`. Mudanças vindas do upstream chegam via merge (ver histórico recente: `Merge remote-tracking branch 'renato-libsignal/master'`). Ao mexer em código, considerar facilidade de futuros merges.
