#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

unsigned int data[65536];
unsigned int a[5];

double cal_entropy(int N, int idx){
	srand(time(NULL));
	int i;
	for(i = 0;i < N;i++){
		data[i] = rand() % a[idx];
	}

	int count[65536];
	for(i = 0;i < N;i++){
		count[i] = 0;
	}
	int index = 0;
	int counter = 0;
	
}


int main(int argc, char ** args){
	a[1] = 0x00ff;
	a[2] = 0xffff;
	a[3] = 0x00ffffff;
	a[4] = 0xffffffff;


}