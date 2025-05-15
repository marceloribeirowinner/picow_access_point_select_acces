/*
 * Projeto: 
 * AccessPoint via Servidor HTTP - Raspberry Pi Pico W
 *
 * Objetivos:
 * - Configurar o Raspberry Pi Pico W como um ponto de acesso (Access Point) Wi-Fi.
 * - Iniciar lista de conexões Wi-Fi locais para permitir a conexão do dispositivo.
 * - Criar um servidor HTTP embarcado que disponibiliza uma página HTML de controle.
 *
 * Funcionalidades:
 * - Criação de uma rede Wi-Fi com nome (SSID) e senha definidos no código.
 * - Atribuição automática de IP aos dispositivos conectados via servidor DHCP.
 * - Interface HTML que permite visualizar lista de redes Wi-Fi.
 * - Carregar a página de lista de redes Wi-Fi, no seguinte endereço: http://192.168.4.1/scan
*/

#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "dhcpserver.h"
#include "dnsserver.h"

#define TCP_PORT 80
#define DEBUG_printf printf
#define POLL_TIME_S 5
#define HTTP_GET "GET"
#define HTTP_POST "POST"
#define HTTP_RESPONSE_HEADERS "HTTP/1.1 %d OK\nContent-Length: %d\nContent-Type: text/html; charset=utf-8\nConnection: close\n\n"
#define LED_TEST_BODY "<html><body><h1>Hello from Pico.</h1><p>Led is %s</p><p><a href=\"?led=%d\">Turn led %s</a></body></html>"
#define LED_PARAM "led=%d"
#define LED_TEST "/ledtest"
#define LED_GPIO 0
#define HTTP_RESPONSE_REDIRECT "HTTP/1.1 302 Redirect\nLocation: http://%s/scan\n\n"

#define WIFI_SCAN_BODY "<html><body><h1>Selecione uma rede Wi-Fi</h1><form action='/connect' method='post'>" \
                      "<select name='ssid'>%s</select><br><br>" \
                      "<input type='password' name='password' placeholder='Senha'><br><br>" \
                      "<input type='submit' value='Conectar'></form></body></html>"

#define WIFI_CONNECT_BODY "<html><body><h1>Conectando à rede...</h1><p>SSID: %s</p><p>Status: %s</p></body></html>"

typedef struct {
    char ssid[32];
    int8_t rssi;
    uint8_t security;
} wifi_network_t;

static wifi_network_t networks[10];
static int network_count = 0;

int wifi_scan_callback(void *env, const cyw43_ev_scan_result_t *result) {
    if (result && network_count < 10) {
        strncpy(networks[network_count].ssid, (char*)result->ssid, sizeof(networks[network_count].ssid) - 1);
        networks[network_count].rssi = result->rssi;
        networks[network_count].security = result->auth_mode;
        network_count++;
    }
    return 0; // continue o scan
}

void start_wifi_scan(void) {
    network_count = 0;
    cyw43_wifi_scan_options_t scan_options = {0};
    cyw43_wifi_scan(&cyw43_state, &scan_options, NULL, wifi_scan_callback);
}

typedef struct TCP_SERVER_T_ {
    struct tcp_pcb *server_pcb;
    bool complete;
    ip_addr_t gw;
} TCP_SERVER_T;

typedef struct TCP_CONNECT_STATE_T_ {
    struct tcp_pcb *pcb;
    int sent_len;
    char headers[128];
    char result[256];
    int header_len;
    int result_len;
    ip_addr_t *gw;
} TCP_CONNECT_STATE_T;

static err_t tcp_close_client_connection(TCP_CONNECT_STATE_T *con_state, struct tcp_pcb *client_pcb, err_t close_err) {
    if (client_pcb) {
        assert(con_state && con_state->pcb == client_pcb);
        tcp_arg(client_pcb, NULL);
        tcp_poll(client_pcb, NULL, 0);
        tcp_sent(client_pcb, NULL);
        tcp_recv(client_pcb, NULL);
        tcp_err(client_pcb, NULL);
        err_t err = tcp_close(client_pcb);
        if (err != ERR_OK) {
            DEBUG_printf("close failed %d, calling abort\n", err);
            tcp_abort(client_pcb);
            close_err = ERR_ABRT;
        }
        if (con_state) {
            free(con_state);
        }
    }
    return close_err;
}

static void tcp_server_close(TCP_SERVER_T *state) {
    if (state->server_pcb) {
        tcp_arg(state->server_pcb, NULL);
        tcp_close(state->server_pcb);
        state->server_pcb = NULL;
    }
}

static err_t tcp_server_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    DEBUG_printf("tcp_server_sent %u\n", len);
    con_state->sent_len += len;
    if (con_state->sent_len >= con_state->header_len + con_state->result_len) {
        DEBUG_printf("all done\n");
        return tcp_close_client_connection(con_state, pcb, ERR_OK);
    }
    return ERR_OK;
}

static bool connect_to_wifi(const char *ssid, const char *password) {
    cyw43_arch_enable_sta_mode();
    
    // Tenta conectar à rede Wi-Fi
    int result = cyw43_arch_wifi_connect_timeout_ms(ssid, password, CYW43_AUTH_WPA2_AES_PSK, 30000);
    
    if (result == 0) {
        return true;
    }
    return false;
}

static int test_server_content(const char *request, const char *params, char *result, size_t max_result_len) {
    int len = 0;

    // Redireciona qualquer rota diferente de /scan, /connect e /ledtest para /scan usando HTTP 302
    if (
        strcmp(request, "/") == 0 ||
        strcmp(request, "/generate_204") == 0 ||
        strcmp(request, "/hotspot-detect.html") == 0 ||
        strcmp(request, "/ncsi.txt") == 0 ||
        strcmp(request, "/favicon.ico") == 0
    ) {
        len = snprintf(result, max_result_len,
            "HTTP/1.1 302 Found\r\n"
            "Location: /scan\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n"
        );
        return len;
    }

    if (strncmp(request, "/scan", 5) == 0) {
        start_wifi_scan();
        sleep_ms(2000); // Aguarde o scan terminar
        char network_options[1024] = {0};
        char *ptr = network_options;

        for (int i = 0; i < network_count; i++) {
            ptr += snprintf(ptr, sizeof(network_options) - (ptr - network_options),
                          "<option value='%s'>%s (%ddBm)</option>",
                          networks[i].ssid, networks[i].ssid, networks[i].rssi);
        }

        len = snprintf(result, max_result_len, WIFI_SCAN_BODY, network_options);
    }
    else if (strncmp(request, "/connect", 8) == 0) {
        char ssid[32] = {0};
        char password[64] = {0};
        
        if (params) {
            sscanf(params, "ssid=%[^&]&password=%s", ssid, password);
            bool success = connect_to_wifi(ssid, password);
            len = snprintf(result, max_result_len, WIFI_CONNECT_BODY, ssid, 
                          success ? "Conectado com sucesso!" : "Falha na conexão");
        }
    }
    else if (strncmp(request, LED_TEST, sizeof(LED_TEST) - 1) == 0) {
        // Get the state of the led
        bool value;
        cyw43_gpio_get(&cyw43_state, LED_GPIO, &value);
        int led_state = value;

        // See if the user changed it
        if (params) {
            int led_param = sscanf(params, LED_PARAM, &led_state);
            if (led_param == 1) {
                if (led_state) {
                    // Turn led on
                    cyw43_gpio_set(&cyw43_state, LED_GPIO, true);
                } else {
                    // Turn led off
                    cyw43_gpio_set(&cyw43_state, LED_GPIO, false);
                }
            }
        }
        // Generate result
        if (led_state) {
            len = snprintf(result, max_result_len, LED_TEST_BODY, "ON", 0, "OFF");
        } else {
            len = snprintf(result, max_result_len, LED_TEST_BODY, "OFF", 1, "ON");
        }
    }
    return len;
}

err_t tcp_server_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    if (!p) {
        DEBUG_printf("connection closed\n");
        return tcp_close_client_connection(con_state, pcb, ERR_OK);
    }
    assert(con_state && con_state->pcb == pcb);
    if (p->tot_len > 0) {
        DEBUG_printf("tcp_server_recv %d err %d\n", p->tot_len, err);

        // Copia a requisição para o buffer
        pbuf_copy_partial(p, con_state->headers, p->tot_len > sizeof(con_state->headers) - 1 ? sizeof(con_state->headers) - 1 : p->tot_len, 0);

        // Trata requisição GET
        if (strncmp(HTTP_GET, con_state->headers, sizeof(HTTP_GET) - 1) == 0) {
            char *request = con_state->headers + sizeof(HTTP_GET); // + espaço
            char *params = strchr(request, '?');
            if (params) {
                if (*params) {
                    char *space = strchr(request, ' ');
                    *params++ = 0;
                    if (space) {
                        *space = 0;
                    }
                } else {
                    params = NULL;
                }
            }

            // Gera o conteúdo da resposta
            con_state->result_len = test_server_content(request, params, con_state->result, sizeof(con_state->result));
            DEBUG_printf("Request: %s?%s\n", request, params);
            DEBUG_printf("Result: %d\n", con_state->result_len);

            // Envia resposta
            con_state->sent_len = 0;
            if (strncmp(con_state->result, "HTTP/1.1", 8) == 0) {
                // Já é um cabeçalho HTTP completo (redirecionamento 302)
                err = tcp_write(pcb, con_state->result, con_state->result_len, 0);
            } else {
                // Envia cabeçalho HTTP padrão + corpo
                con_state->header_len = snprintf(con_state->headers, sizeof(con_state->headers), HTTP_RESPONSE_HEADERS,
                    200, con_state->result_len);
                err = tcp_write(pcb, con_state->headers, con_state->header_len, 0);
                if (err == ERR_OK && con_state->result_len > 0) {
                    err = tcp_write(pcb, con_state->result, con_state->result_len, 0);
                }
            }
            if (err != ERR_OK) {
                DEBUG_printf("failed to write data %d\n", err);
                return tcp_close_client_connection(con_state, pcb, err);
            }
        }
        tcp_recved(pcb, p->tot_len);
    }
    pbuf_free(p);
    return ERR_OK;
}

static err_t tcp_server_poll(void *arg, struct tcp_pcb *pcb) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    DEBUG_printf("tcp_server_poll_fn\n");
    return tcp_close_client_connection(con_state, pcb, ERR_OK); // Just disconnect clent?
}

static void tcp_server_err(void *arg, err_t err) {
    TCP_CONNECT_STATE_T *con_state = (TCP_CONNECT_STATE_T*)arg;
    if (err != ERR_ABRT) {
        DEBUG_printf("tcp_client_err_fn %d\n", err);
        tcp_close_client_connection(con_state, con_state->pcb, err);
    }
}

static err_t tcp_server_accept(void *arg, struct tcp_pcb *client_pcb, err_t err) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    if (err != ERR_OK || client_pcb == NULL) {
        DEBUG_printf("failure in accept\n");
        return ERR_VAL;
    }
    DEBUG_printf("client connected\n");

    // Create the state for the connection
    TCP_CONNECT_STATE_T *con_state = calloc(1, sizeof(TCP_CONNECT_STATE_T));
    if (!con_state) {
        DEBUG_printf("failed to allocate connect state\n");
        return ERR_MEM;
    }
    con_state->pcb = client_pcb; // for checking
    con_state->gw = &state->gw;

    // setup connection to client
    tcp_arg(client_pcb, con_state);
    tcp_sent(client_pcb, tcp_server_sent);
    tcp_recv(client_pcb, tcp_server_recv);
    tcp_poll(client_pcb, tcp_server_poll, POLL_TIME_S * 2);
    tcp_err(client_pcb, tcp_server_err);

    return ERR_OK;
}

static bool tcp_server_open(void *arg, const char *ap_name) {
    TCP_SERVER_T *state = (TCP_SERVER_T*)arg;
    DEBUG_printf("starting server on port %d\n", TCP_PORT);

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!pcb) {
        DEBUG_printf("failed to create pcb\n");
        return false;
    }

    err_t err = tcp_bind(pcb, IP_ANY_TYPE, TCP_PORT);
    if (err) {
        DEBUG_printf("failed to bind to port %d\n",TCP_PORT);
        return false;
    }

    state->server_pcb = tcp_listen_with_backlog(pcb, 1);
    if (!state->server_pcb) {
        DEBUG_printf("failed to listen\n");
        if (pcb) {
            tcp_close(pcb);
        }
        return false;
    }

    tcp_arg(state->server_pcb, state);
    tcp_accept(state->server_pcb, tcp_server_accept);

    printf("Try connecting to '%s' (press 'd' to disable access point)\n", ap_name);
    return true;
}

void key_pressed_func(void *param) {
    assert(param);
    TCP_SERVER_T *state = (TCP_SERVER_T*)param;
    int key = getchar_timeout_us(0); // get any pending key press but don't wait
    if (key == 'd' || key == 'D') {
        cyw43_arch_lwip_begin();
        cyw43_arch_disable_ap_mode();
        cyw43_arch_lwip_end();
        state->complete = true;
    }
}

int main() {
    stdio_init_all();
    
    if (cyw43_arch_init()) {
        printf("Falha ao inicializar CYW43\n");
        return -1;
    }
    
    // Inicializa o modo Access Point
    cyw43_arch_enable_ap_mode("PicoW_AP", "12345678", CYW43_AUTH_WPA2_AES_PSK);
    
    // Configura o servidor TCP
    TCP_SERVER_T *state = calloc(1, sizeof(TCP_SERVER_T));
    if (!state) {
        printf("Falha ao alocar memória para o servidor\n");
        return -1;
    }
    
    // Inicia o servidor TCP
    if (!tcp_server_open(state, "PicoW_AP")) {
        printf("Falha ao iniciar o servidor TCP\n");
        return -1;
    }
    
    // Configura o servidor DHCP
    dhcp_server_t dhcp_server;
    ip4_addr_t gw_addr;
    ip4_addr_t mask_addr;
    
    IP4_ADDR(&gw_addr, 192, 168, 4, 1);
    IP4_ADDR(&mask_addr, 255, 255, 255, 0);
    
    dhcp_server_init(&dhcp_server, &gw_addr, &mask_addr);
    
    // Configura o servidor DNS
    dns_server_t dns_server;
    dns_server_init(&dns_server, &gw_addr);
    
    printf("Servidor iniciado. Conecte-se à rede 'PicoW_AP' com senha '12345678'\n");
    printf("Acesse http://192.168.4.1/scan para selecionar uma rede Wi-Fi\n");
    
    // Loop principal
    while (true) {
        cyw43_arch_poll();
        sleep_ms(1000);
    }
    
    return 0;
}
