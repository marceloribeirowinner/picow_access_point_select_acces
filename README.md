# AccessPoint via Servidor HTTP - Raspberry Pi Pico W

Projeto para transformar o Raspberry Pi Pico W em um ponto de acesso Wi-Fi com servidor HTTP embarcado, permitindo a seleção de redes Wi-Fi próximas e controle de LED via interface web.

---

## Objetivos

- Configurar o Raspberry Pi Pico W como Access Point Wi-Fi.
- Permitir que dispositivos se conectem à rede criada pelo Pico W.
- Disponibilizar uma página HTML para:
  - Listar redes Wi-Fi próximas.
  - Permitir conexão a uma rede Wi-Fi selecionada.

---

## Funcionalidades

- **Criação de rede Wi-Fi**: O Pico W cria uma rede com SSID e senha definidos no código (`PicoW_AP` / `12345678`).
- **Servidor DHCP**: Atribui IP automaticamente aos dispositivos conectados.
- **Servidor HTTP embarcado**: Disponibiliza páginas de controle acessíveis via navegador.
- **Página de seleção de redes**: Lista redes Wi-Fi próximas e permite conexão.

---

## Como funciona

1. **Inicialização**
   - O Pico W ativa o modo Access Point com SSID e senha definidos.
   - Servidores DHCP e DNS são inicializados para gerenciar conexões.

2. **Acesso à interface**
   - Conecte-se à rede Wi-Fi `PicoW_AP` usando a senha `12345678`.
   - Acesse `http://192.168.4.1/scan` pelo navegador.

3. **Seleção de Rede Wi-Fi**
   - A página `/scan` exibe as redes Wi-Fi próximas.
   - Escolha uma rede, insira a senha e clique em "Conectar".
   - O dispositivo tentará conectar à rede escolhida e informará o status.

---

## Endpoints HTTP

| Caminho               | Descrição                                    |
|-----------------------|----------------------------------------------|
| `/scan`               | Página para listar e selecionar redes Wi-Fi  |
| `/connect`            | Recebe dados do formulário para conexão Wi-Fi|
| `/ledtest`            | Página para controle do LED onboard          |
| Outros (`/`, etc)     | Redirecionam automaticamente para `/scan`    |

---

## Exemplo de Fluxo

1. **Conectar à rede criada pelo Pico W**  
   SSID: `PicoW_AP`  
   Senha: `12345678`

2. **Abrir navegador e acessar:**  
   `http://192.168.4.1/scan`

3. **Selecionar uma rede Wi-Fi local e conectar.**


---

## Principais Trechos do Código

- **Configuração do Access Point**
  ```c
  cyw43_arch_enable_ap_mode("PicoW_AP", "12345678", CYW43_AUTH_WPA2_AES_PSK);
  ```

- **Servidor HTTP**
  - Implementado sobre TCP, responde a requisições GET e POST.
  - Redireciona rotas não reconhecidas para `/scan`.
  - Responde com páginas HTML para seleção de rede e controle de LED.

- **Scan de redes Wi-Fi**
  ```c
  cyw43_wifi_scan(&cyw43_state, &scan_options, NULL, wifi_scan_callback);
  ```

- **Conexão a rede Wi-Fi selecionada**
  ```c
  int result = cyw43_arch_wifi_connect_timeout_ms(ssid, password, CYW43_AUTH_WPA2_AES_PSK, 30000);
  ```

---

## Dependências

- Raspberry Pi Pico W
- SDK do Pico
- Bibliotecas: `cyw43_arch`, `lwip`, `dhcpserver`, `dnsserver`

---

## Observações

- O projeto foi desenvolvido em C, utilizando o SDK oficial do Raspberry Pi Pico.
- O código pode ser expandido para incluir outras funcionalidades de controle e monitoramento.

---

## Uso

1. Compile o projeto utilizando o SDK do Pico.
2. Grave o firmware no Raspberry Pi Pico W.
3. Siga o fluxo descrito acima para utilizar a interface web.

---

## Créditos

Desenvolvido para demonstração de uso do Raspberry Pi Pico W como Access Point e servidor HTTP embarcado.

Citations:
[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/56740203/eb7ee54d-f8d9-4dac-ade1-838fec90ba37/paste.txt
[2] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/56740203/eb7ee54d-f8d9-4dac-ade1-838fec90ba37/paste.txt
