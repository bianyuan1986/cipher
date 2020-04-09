#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

#define VECTOR_SIZE 256
#define RULE_FILE_NAME "ms_rule.data"

#define OPTION_UNKNOWN 0
#define OPTION_ENCRYPT 1
#define OPTION_DECRYPT 2

#define MIX_CHAR(k, n)   ((k>>n)|(k<<(8-n)))
#define RESTORE_CHAR(k, n) ((k>>(8-n))|(k<<n))

#define RC4_PRINT(format, args...)\
	do\
	{\
		if( gCfg.debug )\
		{\
			printf(format, ##args);\
		}\
	}while(0)

struct rc4
{
	int S[VECTOR_SIZE];
	int T[VECTOR_SIZE];
	unsigned char *finalKey;
	int kLen;
	int encryptLen;
};

struct globalConfig
{
	int action;
	char *filename;
	char *initKey;
	char *dir;
	int kLen;
	int debug;
};

extern char *optarg;
extern int optind;

struct globalConfig gCfg;
struct rc4 r;

int get_random()
{
	int random = 0;
	int fd = 0;
	unsigned long seed = 0;

	fd = open("/dev/urandom", O_RDONLY);
	if( fd < 0 || read(fd, &seed, sizeof(seed)) < 0 )
	{
		seed = time(NULL);
	}
	if( fd > 0 )
	{
		close(fd);
	}
	srand(seed);
	random = rand();

	return random;
}

void rc4_init(struct rc4 *r, char *initKey, int kLen)
{
	int i = 0;

	for( ; i < VECTOR_SIZE; i++)
	{
		r->S[i] = i;
		r->T[i] = initKey[i%kLen];
	}
}

/*Key-Scheduling Algorithm*/
void rc4_ksa(struct rc4 *r)
{
	int i = 0;
	int j = 0;
	int tmp = 0;
	for( i = 0; i < VECTOR_SIZE; i++)
	{
		j = (j + r->S[i] + r->T[i]) % VECTOR_SIZE;

		tmp = r->S[j];
		r->S[j] = r->S[i];
		r->S[i] = tmp;
	}
}

/*Pseudo-random generation algorithm*/
void rc4_prga(struct rc4 *r, int len)
{
	int i = 0;
	int j = 0;
	int k = 0;
	int t = 0;
	int tmp = 0;

	r->kLen = len;
	r->finalKey = (unsigned char*)malloc(len);

	for( ; k <= len; k++)
	{
		i = (i+1)%VECTOR_SIZE;
		j = (j + r->S[i])%VECTOR_SIZE;

		tmp = r->S[i];
		r->S[i] = r->S[j];
		r->S[j] = tmp;

		t = (r->S[i] + r->S[j])%VECTOR_SIZE;
		r->finalKey[k] = r->S[t];
	}
}

void rc4_dump(struct rc4 *r)
{
	int i = 0;

	RC4_PRINT("Key stream:\n");
	for( ; i < r->kLen; i++)
	{
		RC4_PRINT("%03d ", r->finalKey[i]);
	}
	RC4_PRINT("\n");
}

void rc4_encrypt(struct rc4 *r, char *plainText, int len)
{
	int i = 0;

	RC4_PRINT("PlainText:\n%s\n", plainText);
	while( i < len )
	{
		plainText[i] = plainText[i] ^ r->finalKey[r->encryptLen%r->kLen];
		r->encryptLen++;
		i++;
	}
}

unsigned char *map_file(char *filename, int len)
{
	unsigned char *data = NULL;
	int fd = 0;
	int ret = 0;

	fd = open(filename, O_CREAT|O_RDWR, 0644);
	ret = ftruncate(fd, len);
	if( ret < 0 )
	{
		RC4_PRINT("Truncate file %s failed:%s\n", filename, strerror(errno));
		goto FAILED;
	}
	data = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if( data == MAP_FAILED )
	{
		RC4_PRINT("Mmap file %s failed:%s\n", filename, strerror(errno));
		goto FAILED;
	}
	close(fd);

	return data;

FAILED:
	return NULL;
}

int encrypt_file(struct rc4 *r, char *filename)
{
	FILE *f = NULL;
	int ret = 0;
	char *line = NULL;
	size_t size = 0;
	char *cipherText = NULL;
	int total_size = 0;
	struct stat st;
	int fd = 0;
	unsigned char *data = NULL;
	int dLen = 0;
	int i = 0;
	int shift_cnt = 0;

	ret = access(filename, F_OK);
	if( ret < 0 )
	{
		RC4_PRINT("File %s doesn't exist!\n", filename);
		goto FAILED;
	}
	ret = stat(filename, &st);
	if( ret < 0 )
	{
		RC4_PRINT("Stat file %s failed:%s\n", filename, strerror(errno));
		goto FAILED;
	}
	f = fopen(filename, "r");
	if( !f )
	{
		RC4_PRINT("Open file %s failed:%s\n", filename, strerror(errno));
		goto FAILED;
	}

	total_size = 1 + 1 + r->kLen + st.st_size;
	data = map_file(RULE_FILE_NAME, total_size);
	if( !data )
	{
		goto FAILED;
	}

	data[dLen++] = r->kLen;
	data[dLen++] = get_random()%0x7+0xF1;
	shift_cnt = data[1]&0xF;
	for( ; i < r->kLen; i++)
	{
		data[dLen+i] = MIX_CHAR(r->finalKey[i], shift_cnt);
		data[dLen+i] ^= data[1];
	}
	dLen += r->kLen;
	while( (ret = getline(&line, &size, f)) != -1 )
	{
		rc4_encrypt(r, line, ret);
		if( dLen + ret > total_size )
		{
			RC4_PRINT("Error occured!\n");
			goto FAILED;
		}
		memcpy(&data[dLen], line, ret);
		dLen += ret;
	}
	RC4_PRINT("Total size:%d Copyed:%d!\n", total_size, dLen);
	if( r->encryptLen != st.st_size )
	{
		printf("Encrypt failed!\n");
		goto FAILED;
	}

	if( line )
	{
		free(line);
	}
	if( f )
	{
		fclose(f);
	}
	msync(data, total_size, MS_SYNC);
	munmap(data, total_size);

	return 0;

FAILED:
	return -1;
}

int decrypt_file(struct rc4 *r, char *filename)
{
	unsigned char *data = NULL;
	struct stat st;
	int ret = 0;
	int i = 0;
	int shift_cnt = 0;
	int data_start = 0;
	int max = 0;

	ret = stat(filename, &st);
	if( ret < 0 )
	{
		RC4_PRINT("Stat file failed:%s\n", strerror(errno));
		goto FAILED;
	}
	data = map_file(filename, st.st_size);
	if( !data ||
			(data[0] >= st.st_size) ||
			(st.st_size < 4) )
	{
		goto FAILED;
	}
	r->kLen = data[0];
	shift_cnt = data[1]&0xF;
	r->finalKey = (unsigned char*)malloc(data[0]);
	for( ; i < data[0]; i++)
	{
		r->finalKey[i] = data[i+2] ^ data[1];
		r->finalKey[i] = RESTORE_CHAR(r->finalKey[i], shift_cnt);
	}
	data_start = 2 + r->kLen;
	max = st.st_size - data_start;
	for(i = 0; i < max; i++)
	{
		data[i] = data[data_start+i] ^ r->finalKey[i%r->kLen];
	}
	for( ; i < st.st_size; i++)
	{
		data[i] = ' ';
	}
	msync(data, st.st_size, MS_SYNC);
	munmap(data, st.st_size);

	return 0;

FAILED:
	return -1;
}

int parse_arg(int argc, char *argv[], struct globalConfig *cfg)
{
	int opt = 0;
	int len = 0;

	while( (opt = getopt(argc, argv, "e:d:k:p:gh")) != -1 )
	{
		switch(opt)
		{
			case 'p':
				cfg->dir = optarg;
				break;
			case 'e':
				cfg->action = OPTION_ENCRYPT;
				cfg->filename = optarg;
				break;
			case 'd':
				cfg->action = OPTION_DECRYPT;
				cfg->filename = optarg;
				break;
			case 'k':
				len = strlen(optarg);
				if( len >= 256 )
				{
					printf("Init key length can't exceed limit 256!\n");
					goto FAILED;
				}
				cfg->initKey = malloc(len+1);
				memcpy(cfg->initKey, optarg, len);
				cfg->initKey[len] = '\0';
				cfg->kLen = len;
				break;
			case 'g':
				cfg->debug = 1;
				break;
			case 'h':
				printf("Usage:%s -e FILENAME -k INITKEY\n      %s -d FILENAME\n", argv[0], argv[0]);
				break;	
			default:
				RC4_PRINT("Usage:%s -e FILENAME -k INITKEY\n      %s -d FILENAME\n", argv[0], argv[0]);
				goto FAILED;
		}
	}

	if( cfg->action == OPTION_UNKNOWN )
	{
		RC4_PRINT("Please specify option [-e|-d]!\n");
		goto FAILED;
	}

	if( (cfg->action == OPTION_ENCRYPT) && (cfg->initKey == NULL) )
	{
		RC4_PRINT("Please specify initKey!\n");
		goto FAILED;
	}

	return 0;

FAILED:
	exit(1);
}

void init_cfg(struct globalConfig *cfg)
{
	memset(cfg, 0x00, sizeof(struct globalConfig));
}

int main(int argc, char *argv[])
{
	int len = 0;
	int ret = 0;
	int keyStreamLen = 0;

	init_cfg(&gCfg);
	parse_arg(argc, argv, &gCfg);

	memset(&r, 0x00, sizeof(struct rc4));
	switch(gCfg.action)
	{
		case OPTION_ENCRYPT:
			rc4_init(&r, gCfg.initKey, gCfg.kLen);
			rc4_ksa(&r);
			keyStreamLen = get_random()%64+64;
			rc4_prga(&r, keyStreamLen);
			rc4_dump(&r);
			ret = encrypt_file(&r, gCfg.filename);
			break;
		case OPTION_DECRYPT:
			ret = decrypt_file(&r, gCfg.filename);
			break;
		default:
			RC4_PRINT("Unknown action!\n");
	}

	return ret;
}

