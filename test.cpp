#include <Arduino.h>
#include <EEPROM.h>

#include <config.h>

#include <WiFi.h>
#include <WiFiUdp.h>
WiFiUDP mcast;
WiFiUDP ntpUDP;

#include <NTPClient.h>
NTPClient timeClient(ntpUDP, "europe.pool.ntp.org", 0, 300 * 1000);

#include <ArduinoJson.h>

StaticJsonDocument<1024> Data;
StaticJsonDocument<1024> Data_Payload;

#include <Crypto.h>
#include <ChaChaPoly.h>
ChaChaPoly chacha;

#include <byteswap.h>
#include <libb64/cdecode.h>


#define IETF_ABITES  16
typedef union {
  unsigned char buf[12];
  struct {
    uint64_t sec;
    uint32_t usec; };
} nonce_t;

void wifiInit() {
  Serial.print("# Init WiFi\n");
  WiFi.begin(SSID, PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
  Serial.print("# WiFi connected\n");
  Serial.print("# IP address: ");
  Serial.println(WiFi.localIP());
  mcast.beginMulticast(IPAddress(224,0,29,200),PORT);
}

void ntpInit() {
  timeClient.update();
  Serial.println("# Time : " + timeClient.getFormattedTime());
}

void setup()
{

  Serial.begin(115200);   // Starts serial communication in 9600 baud rate.
  wifiInit();
  ntpInit();
}

void loop(){
  //test();

  char buf[1024];
  nonce_t nonce;
  unsigned long sec,usec;
  int b64_len;
  char *b64;
  uint8_t *pjson; 
  uint16_t size;
  base64_decodestate b64_state;

   if (WiFi.status() != WL_CONNECTED) {
    Serial.print("# Error: no network\n");
    return;
  }

  // if there's data available, read a packet
  //Serial.println(mcast.available());
  int packetSize = mcast.parsePacket();
  if (packetSize) {
    // read the packet into packetBufffer
    int len =  mcast.read((char *) &buf,1024);
    if (len > 0) {
      buf[len] = 0;
    }
    Serial.println("Contents:");
    Serial.println(buf);

    DeserializationError error_json = deserializeJson(Data,buf);

    if (error_json){
      Serial.println("Unable to parse JSON data");
      return;
    }

    const char* targets = Data["targets"];
    Serial.print("targets : ");
    Serial.println(targets);
    
    JsonArray timestamp = Data["timestamp"];
    Serial.print("timestamp : ");
    long sec = timestamp[0];
    long usec = timestamp[1];
    Serial.print(sec);
    Serial.print(" , ");
    Serial.println(usec);


  
    // let's base64 decode the payload
    // add one byte for NULL end, if not free() will crash.

    const char* payload = Data["payload"];

    size = strlen(payload) + IETF_ABITES;
    b64_len = base64_decode_expected_len(size)+1; 
    b64 = (char *) malloc(b64_len);
    base64_init_decodestate(&b64_state);
    b64_len = base64_decode_block(payload, size, b64, &b64_state);

     // Init chacha cipher 
    chacha.clear();
    chacha.setKey(XAAL_KEY,32);

    // additionnal data
    chacha.addAuthData("[]",2);

    // Nonce 
    
    nonce.sec = __bswap_64(sec);
    nonce.usec = __bswap_32(usec);
    chacha.setIV(nonce.buf,12);
  
  
    pjson  = (uint8_t *) malloc(sizeof(uint8_t) * (size));
    chacha.decrypt(pjson ,(const uint8_t*)b64,strlen(b64));
    chacha.computeTag(pjson,sizeof(pjson));

    deserializeJson(Data_Payload,pjson);

    const char* header = Data_Payload["header"]; //header
    Serial.print("header : ");
    Serial.println(header);

    const char* body = Data_Payload ["body"];
    Serial.print("body : ");
    Serial.println(body);

  }

  delay(1000);
}
