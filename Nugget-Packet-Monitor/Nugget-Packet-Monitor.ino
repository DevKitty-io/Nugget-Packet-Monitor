#include "SH1106Wire.h"
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "graphics.h"

SH1106Wire display(0x3C, 33, 35);

String src; String dst;
char srcOctet[2], dstOctet[2];

#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

uint8_t level = 0, channel = 1;

static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13}; //Most recent esp32 library struct

typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event)
{
  return ESP_OK;
}

void wifi_sniffer_init(void)
{
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel)
{
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  display.clear();
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  Serial.printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
    " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
    " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
    " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
    wifi_sniffer_packet_type2str(type),
    ppkt->rx_ctrl.channel,
    ppkt->rx_ctrl.rssi,
    /* ADDR1 */
    hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
    hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
    /* ADDR2 */
    hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
    hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
    /* ADDR3 */
    hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
    hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
  );

//  display.drawXbm(0,0,128,64,invader_bits);/

  src = ""; 
  for (int j= 0; j< 6; j++) { 
    sprintf(srcOctet, "%02x", hdr->addr2[j]); src+=srcOctet;
//    if (j!=5) src+=":";/
  }
  dst = "";
  for (int i= 0; i< 6; i++) { 
    sprintf(dstOctet, "%02x", hdr->addr1[i]); dst+=dstOctet;
//    if (i!=5) dst+=":";/
  }
  
  
  dst.toUpperCase();
  src.toUpperCase();
  display.drawXbm(Navbar_Outline_x_hot, Navbar_Outline_y_hot, Navbar_Outline_width, Navbar_Outline_height, Navbar_Outline_bits);
  display.drawXbm(Arrow_Left_x_hot, Arrow_Left_y_hot, Arrow_Left_width, Arrow_Left_height, Arrow_Left_bits);
  display.drawXbm(Arrow_Right_x_hot, Arrow_Right_y_hot, Arrow_Right_width, Arrow_Right_height, Arrow_Right_bits);
  display.drawXbm(Window_Header_x_hot, Window_Header_y_hot, Window_Header_width, Window_Header_height, Window_Header_bits);

  display.drawString(((104 - ::display.getStringWidth("PACKET MONITOR")) / 2) + 12, 54, "PACKET MONITOR");
  
  display.drawString(3,0,"PKT: " + (String) wifi_sniffer_packet_type2str(type)); // packet type
  display.drawString(94,0,"CH:" + (String) ppkt->rx_ctrl.channel); // channel
  display.drawString(0,17,"SRC: " + src); // source MAC
  display.drawString(0,27,"DST: " + dst);

  display.drawString(0,37,"RSSI: " + (String) ppkt->rx_ctrl.rssi);
  
  

//  display.drawString(); // dest MAC/
  
  display.display();
}

void setup() {
  Serial.begin(115200);
  display.init();
  display.flipScreenVertically();
  display.setTextAlignment(TEXT_ALIGN_LEFT);
  display.setFont(DejaVu_Sans_Mono_10);
  
  delay(10);
  wifi_sniffer_init();
}

// the loop function runs over and over again forever
void loop() {
  //Serial.print("inside loop");
  delay(1000); // wait for a second
  
  vTaskDelay(WIFI_CHANNEL_SWITCH_INTERVAL / portTICK_PERIOD_MS);
  wifi_sniffer_set_channel(channel);
  channel = (channel % WIFI_CHANNEL_MAX) + 1;
}
