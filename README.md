# Marksaint Vault

Aplicativo web seguro para equipes B2B gerenciarem contas de e-mail, senhas e o mapeamento de aplicativos utilizados. Inclui autenticação de dois fatores, criptografia ponta a ponta e dashboard com alertas de vulnerabilidade.

## Recursos principais

- Dashboard com visão geral, alertas de rotação e recomendações de boas práticas.
- Diretório de e-mails com indicador visual de uso e filtros por status.
- CRUD completo de credenciais com busca por e-mail/aplicativo e filtros de rotação.
- Criptografia robusta (Fernet/AES-256) para todos os dados sensíveis.
- Login com senha administrativa + TOTP (2FA).
- Notificações visuais para troca periódica de senhas.
- Exportação segura de dados usando PBKDF2 + Fernet.

## Executando localmente

1. Crie um ambiente virtual e instale as dependências:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Defina as variáveis de ambiente:

   ```bash
   export MARKSAINT_STORAGE_KEY="$(python - <<'PY'
import base64, os
print(base64.urlsafe_b64encode(os.urandom(32)).decode())
PY
)"
   export MARKSAINT_APP_SECRET="$(python - <<'PY'
import os
print(os.urandom(32).hex())
PY
)"
   export MARKSAINT_TOTP_SECRET="JBSWY3DPEHPK3PXP"  # troque e adicione ao seu app autenticador
   export MARKSAINT_ADMIN_PASSWORD_HASH="$(python - <<'PY'
from werkzeug.security import generate_password_hash
print(generate_password_hash('SenhaSuperForte!'))
PY
)"
   ```

3. Inicialize o diretório de e-mails (opcional) cadastrando endereços em `/emails` para mapear responsáveis, serviços e status. As credenciais sempre se vinculam a um e-mail registrado e exibem automaticamente o uso.

4. Execute o servidor:

   ```bash
   flask --app app run
   ```

5. Acesse `http://localhost:5000/login`, faça login com a senha definida e informe o token TOTP correspondente.

## Exportação segura

Na tela "Exportação segura" informe uma frase-senha. O sistema derivará uma chave usando PBKDF2 (390k iterações) e criará um arquivo `.bin` contendo o JSON criptografado. Para abrir posteriormente, use o mesmo salt (armazenado nos 16 bytes iniciais do arquivo) e a frase-senha utilizada.
