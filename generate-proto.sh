yarn pbjs -t static-module -w commonjs -o ./src/WhisperTextProtocol.js ./protos/WhisperTextProtocol.proto
yarn pbts -o ./src/WhisperTextProtocol.d.ts ./src/WhisperTextProtocol.js
