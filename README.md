# LOSPICHOS DEFENDER

Aplicação web que consulta a reputação de uma URL no VirusTotal e mostra os resultados individuais dos mecanismos antivírus.

## Funcionalidades

- envio da URL ao VirusTotal para análise
- espera pela conclusão da análise antes de mostrar o resultado
- lista de resultados dos mecanismos do VirusTotal
- interface web servida pelo próprio backend

## Estrutura do projeto

```text
site virustotal/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
└── web-scanner/
    └── backend/
```

## Como rodar localmente

1. Clone o projeto
2. Entre na pasta do projeto
3. Instale as dependências:

```bash
pip install -r requirements.txt
```

4. Configure a chave do VirusTotal no arquivo `.env` na raiz do projeto:

```text
VT_API_KEY=sua_chave_do_virustotal
```

O arquivo `.env` está no `.gitignore` e não deve ser enviado ao GitHub.

5. Inicie o servidor:

No Windows PowerShell:

```powershell
cd "c:\Users\SEU_USUARIO\Downloads\PROJETOS\site virustotal"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Abra `http://127.0.0.1:8000/`. O backend serve a interface e a API na mesma origem.

## Publicar no Render

1. Envie o conteúdo do projeto para um repositório GitHub, sem incluir `.env`.
2. No Render, crie um Blueprint a partir desse repositório. O arquivo `render.yaml` configura a instalação, o comando de inicialização e o health check.
3. Nas variáveis de ambiente do serviço, configure `VT_API_KEY` com sua chave do VirusTotal. Não coloque a chave no código nem no GitHub.
4. Faça o deploy e abra a URL pública fornecida pelo Render.

O endpoint `/health` deve responder `{"status":"ok"}`. O plano gratuito do Render pode suspender o serviço após inatividade e levar alguns instantes para iniciar novamente.

## Observação

Uma análise concluída sem detecções não garante que uma URL seja segura. O VirusTotal pode retornar mecanismos sem veredito e está sujeito a limites de uso da API.

## Licença

Este projeto é disponibilizado apenas para fins educacionais.
