#include <stdio.h>
#include <stdint.h> // for uint8_t
#include <netinet/in.h> // for ntohs, ntohl

int main(int argc, char* argv[]) {
	
	if (argc < 2) {
  printf("syntax : sum-nbo <file>\n");
  return 1;
}

uint32_t result = 0;

	for(int i = 1; i < argc; i++){
	FILE* filePointer = fopen(argv[i], "rb");
    
  if (filePointer == NULL) {
	  printf("File open XXX.\n");
    return 1;
  }
  
  
    
  if(filePointer != NULL){
	  uint32_t num;
	  if (fread(&num, sizeof(uint32_t), 1, filePointer) != 1) {
	  printf("File is smaller than 4bytes\n");
	  fclose(filePointer);
	  return 1;
} 
    num = ntohl(num);
    result += num;
  
  }
  
  
  fclose(filePointer);  
  }
  printf("%u\n", (unsigned int)result);
  return 0;
} 
