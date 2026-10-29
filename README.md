# CostLens — demonstração

Site estático da demonstração do CostLens (should-cost e DFM a partir do CAD).

O app e os exemplos ficam **cifrados** em `vault/` (AES-256-GCM, chave derivada da senha com PBKDF2-SHA256).
A página de entrada pede a senha, deriva a chave no navegador e um service worker (`sw.js`) decifra os
arquivos sob demanda. Sem a senha, este repositório só contém dados embaralhados.

Gerado automaticamente; não edite à mão. Avisos de licença de terceiros (OpenCascade/occt-import-js, LGPL-2.1)
em `licenses/`.
