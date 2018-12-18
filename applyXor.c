#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int_least32_t sizeFile(FILE * restrict);
void readFile(char * restrict);
void writeFile(unsigned char * restrict, int_least32_t, char * restrict);
long decryptHeader(unsigned char * restrict, int_least32_t);
unsigned char decryptFile(unsigned char * restrict, int_least32_t);

int main(int argc, char **argv)
{
	if (argc == 2)
	{
		readFile(argv[1]);

 		return EXIT_SUCCESS;
	}
	else
		return EXIT_FAILURE;
 		
}

void readFile(char * restrict fileName)
{
	FILE * restrict rfile = fopen(fileName, "rb");
	int_least32_t size = sizeFile(rfile), offset = 0x0;
	unsigned char key = '\0';
 	unsigned char * restrict bin = (unsigned char *)calloc(size, 0x1), 
 			 	  * restrict noHeader = NULL;

 	fread(bin, size, 0x1, rfile);
 	offset = decryptHeader(bin, size);
 	noHeader = (unsigned char *)calloc(size - offset, 0x1);

 	for (int_fast64_t i = 0; i < size - offset; i++)
 		noHeader[i] = bin[offset + i];

 	key = decryptFile(noHeader, size - offset);

 	if (key)
 	{
 		writeFile(noHeader, size - offset, fileName);
 		printf("\nLa llave es: %x\n%s %s%s", key, 
 			   "El archivo se ha guardado con el nombre",
 			   fileName ,"\n");
 	}
 	else
 		printf("No se encontro una llave que coincidiera\n");

 	free(bin);
 	free(noHeader);
 	fclose(rfile);
}

void writeFile(unsigned char * restrict bin, int_least32_t size, 
			   char * restrict fileName)
{
	FILE * restrict wfile = fopen(strcat(fileName, ".decrypt"), "wb");

	fwrite(bin, 0x1, size, wfile);
	fclose(wfile);
}


/*
	Se encuentra el tamaño del archivo en total para apartar
	la memoria necesaria para su funcionamiento
*/
int_least32_t sizeFile(FILE * restrict file)
{
	int_least32_t size;

	fseek(file, 0, SEEK_END);
	size = ftell(file);
	rewind(file);

	return size;
}

/*
	Se conoce que el archivo esta cifrado con la operación xor con la llave
	0x5A debido a trabajos de otras personas y usando esta información es posible
	usar las posiciones del header para identificar el final del segmento
	añadido por symantec al archivo original, eliminarlo y comenzar con la
	fuerza bruta en el archivo original.
*/
long decryptHeader(unsigned char * restrict bin, int_least32_t size)
{
	//En la posicion 0xD54 se guarda un entero de 4 bytes que almacena
	//el tamaño del archivo antes de ser puesto en cuarentena
	int32_t unSize = (((int32_t)bin[0xD57]) << 24) | 
					 (((int32_t)bin[0xD56]) << 16) |
					 (((int32_t)bin[0xD55]) <<  8) |
					 ((int32_t)bin[0xD54]);

	//Tamaño de la cabecera de metadatos del archivo en cuarentena
	int32_t metaSize = (((int32_t)bin[0x12A3] ^ 0x5A) << 24) |
					   (((int32_t)bin[0x12A2] ^ 0x5A) << 16) |
					   (((int32_t)bin[0x12A1] ^ 0x5A) <<  8) |
					   ((int32_t)bin[0x12A0] ^ 0x5A);

	/*
		Sumando el inicio del segmento de metadatos del archivo al tamaño
	  	de la cabecera de metadatos mas otros metadatos conocidos se obtiene
		el siguiente valor de desplazamiento:
		0x12B8 + 708 + 6D que esta en la posicion indicada en el arreglo bin
	*/
	int32_t offset = 0x12B8 + metaSize + 0x6D; //offset en el archivo

	int32_t quaSize = (((int32_t)bin[offset + 3] ^ 0x5A) << 24) |
					  (((int32_t)bin[offset + 2] ^ 0x5A) << 16) |
					  (((int32_t)bin[offset + 1] ^ 0x5A) <<  8) |
					  ((int32_t)bin[offset] ^ 0x5A);

	//Se añade un salto del tamaño de un entero de 4 bytes, el tamaño del arhivo
	offset = offset + 4;

	//Se busca por el terminador del bloque de metadatos
	while ((bin[offset] ^ 0x5A) != 0x09)
		++offset;

	/*
		Entre el final de la cabecera añadida por symantec y el archivo cifrado
		se añade un segmento de datos basura, el cual se calcula restando el
		tamaño del archivo original al tamaño del archivo en cuarentena.
		El 5 que se suma porque tras el terminador de cadena se agrega de nuevo
		el valor del archivo puesto en cuarentena, se indica el tamaño del 
		bloque cifrado junto con la basura que tiene, esto es un entero de 4
		bytes mas el salto del propio 0x9 hacia el entero de 4 bytes.
	*/
	return offset + (quaSize - unSize + 5); 
}

/*
	En esta funcion se prueban las posibles combinaciones de la llave.
	Se ha eliminado la cabecera de symantec del inicio y se prueban las
	combinaciones para encontrar la letra M inicial.
*/
unsigned char decryptFile(unsigned char * restrict bin, int_least32_t size)
{
	unsigned char chr;

	for (int_fast8_t i = 0x0; i < 0xFF; i++)
	{
		chr = bin[0] ^ i; //Prueba las 256 combinaciones

		if (chr == 'M') //Una vez que encuentra la llave descifra el archivo
		{
			for (int_fast64_t j = 0; j < size; j++)
				bin[j] = bin[j] ^ i;

			return (unsigned char)i;
		}
	}

	return (unsigned char)0x0;
}