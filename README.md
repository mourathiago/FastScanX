<a><img src="https://github.com/user-attachments/assets/52dc90e4-81fe-436a-8dce-b164c8de15ca" alt="FastScanX"></a>

🛠️ FastScanX — Escaneie como um fantasma. Ataque como uma tempestade.
---


# 🚀 FastScanX:
Scanner de portas TCP rápido, com visual moderno no terminal, exportação de resultados e integração com Shodan.

---

## 🛠️ Funcionalidades:

- Escaneamento de portas TCP com feedback em tempo real (barra de progresso).
- Exportação de resultados em JSON e CSV.
- Interface interativa no terminal com `Textual` (UI opcional).
- Consulta enriquecida com dados do Shodan (vulnerabilidades, localização, ISP, etc).
- Exibição de banners dos serviços (quando disponível).
- Suporte a intervalo de portas (`-p 20-80`).
- Código 100% em Python 3.

---

## 📦 Instalação
Clone o repositório:

` git clone https://github.com/SEU_USUARIO/FastScanX.git
cd FastScanX `

---

## ⚙️ Configuração do Shodan
Crie um arquivo config.json com sua API key:

`{
  "shodan_api_key": "SUA_CHAVE_API"
} 
`
 * Exemplo de arquivo disponível em `config.json.example`

---
## ▶️ Uso

```python3 fastscanx.py <IP> [opções]```

## 🔧 Exemplos:
* Escanear portas padrão (20–1024):

```python3 fastscanx.py 192.168.0.1```

* Escanear um intervalo específico:
  
`python3 fastscanx.py 192.168.0.1 -p 80-100`

* Exportar resultados:
  
`python3 fastscanx.py 192.168.0.1 --export json`

* Usar interface com Textual:
  
`python3 fastscanx.py 192.168.0.1 --ui`

* Enriquecer com dados do Shodan:
  
`python3 fastscanx.py 192.168.0.1 --shodan`

---

## 🧾Histórico de Versões:
Veja CHANGELOG.md para detalhes sobre cada versão.
