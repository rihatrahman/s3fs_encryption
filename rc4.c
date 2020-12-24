#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>  
#include <sys/types.h>
#include <unistd.h>    
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rc4.h>
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#define BUFFSIZE 3000000

int main(int argc, char *argv[])
{
    RC4_KEY key;
    char salt[8];
    char buffer[BUFFSIZE];
    char outputBuffer[BUFFSIZE];
    unsigned char x[16];
    unsigned char *saltPtr = NULL;
    static const char salted[] = "Salted__";


	if (argc < 6) {
		perror("Not enough arguments. Please check the readme file.\n");
		exit(1);
	}

	char *ED = argv[1];
	char *input = argv[2];
	char *output = argv[3];
	char *password = argv[4];
	char *saltOrNosalt = argv[5];
    
    int in= open(input, O_RDONLY);
    int out = open(output, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    if (in < 0)
        exit(1);
    

    if (strcmp(saltOrNosalt,"salt") == 0) {
        if (strcmp(ED,"e") == 0)
        {
            RAND_bytes(salt, sizeof(salt));
            write(out,salted,8);
            write(out,salt,sizeof(salt));
        }

        else if (strcmp(ED, "d") == 0) {
            lseek(in, 8, SEEK_SET);
            read(in, salt, 8);
            lseek(in, 16, SEEK_SET);
        }
        saltPtr = salt;
    }

    int sizeofInput = read(in, buffer, BUFFSIZE);

    EVP_BytesToKey(EVP_rc4(), EVP_sha256(), saltPtr, (const unsigned char *)password, strlen(password), 1, x, NULL);

    int len = sizeof(x);

    RC4_set_key(&key, len, (const unsigned char*) x);

    RC4(&key, sizeofInput, (const unsigned char*) buffer, (unsigned char*) outputBuffer);

    lseek(out,0,SEEK_END);
    write(out, outputBuffer, sizeofInput);


    return 0;
}