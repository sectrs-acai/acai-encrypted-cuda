#LD_LIBRARY_PATH=/usr/local/gdev/lib64 ./gaussian ../../data/gaussian/matrix1024.txt
C=$(pwd)
cd ../
./install.sh

cd $C
make clean
make gcc
cd src
sudo LD_LIBRARY_PATH=/usr/local/gdev/lib64/:../../install/lib ./../cuda_enc_app

