#!/usr/bin/env bash
set -u

IMPL_FILE=aes_gpu_impl.h
ECB_FILE=aes_cuda_ecb.h
CTR_FILE=aes_cuda_ctr.h

rm -f $IMPL_FILE $ECB_FILE $CTR_FILE

# BTB implementations, DIAGKEY
for BTB in BTB32DIAGKEY BTB32SRDIAGKEY; do
    for PRMT in C PRMT PRMT8AS32; do
        for PRSZ in 8 32; do
            gen=1
            com=0
            if test $PRMT == PRMT8AS32; then
                if test $PRSZ -eq 32; then
                    gen=0;
                fi
            fi
            if test $PRMT == C; then
                com=1;
            fi
            if test $PRMT == PRMT8AS32; then
                com=1;
            fi
            if test $gen -eq 1; then
                if test $com -eq 1; then
                    echo "#ifdef GPU_CREATE_ALL" >> $IMPL_FILE
                fi
                echo "FUNC_AES_ALL_FT_PP($BTB,0,$PRMT,$PRSZ,PREROUNDS_DIAGKEY,POSTROUNDS_DIAGKEY)" >> $IMPL_FILE
                if test $com -eq 1; then
                    echo "#endif // GPU_CREATE_ALL" >> $IMPL_FILE
                fi
                for LD in nocoal coal coalshuf; do
                    for ST in nocoal coal coalshuf; do
                        gen=1
                        if test $LD == coal -a $ST == coalshuf; then
                            gen=0;
                        fi
                        if test $LD == coalshuf -a $ST == coal; then
                            gen=0;
                        fi
                        if test $gen == 1; then
                            echo "TEST_CUDA(aes_edrk_diag, FT0, NULL, NULL, NULL, NULL, NULL, aes_encrypt_cuda_"$BTB"0_"$PRMT"_"$PRSZ$LD$ST", 1);" >> $ECB_FILE
                            echo "TEST_CUDA(aes_edrk_diag, FT0, NULL, NULL, NULL, IV, NULL, aes_ctr_cuda_"$BTB"0_"$PRMT"_"$PRSZ$LD$ST", 1);" >> $CTR_FILE
                        fi
                    done
                done
            fi
        done
    done
done
echo "#ifdef GPU_CREATE_ALL" >> $IMPL_FILE
# BTB implementations, no diagkey
for BTB in BTB BTB32 BTB32SR BTB32T2 BTB32T2H; do
    for PRMT in C PRMT PRMT8AS32; do
        for PRSZ in 8 32; do
            gen=1
            des=0
            if test $PRMT == PRMT8AS32; then
                if test $PRSZ -eq 32; then
                    gen=0;
                fi
            fi
            if test $BTB == BTB32T2; then
                des=1;
            fi
            if test $BTB == BTB32T2H; then
                des=1;
            fi
            if test $gen -eq 1; then
                if test $des -eq 1; then
                    echo "#if 0" >> $IMPL_FILE
                fi
                echo "FUNC_AES_ALL_FT($BTB,0,$PRMT,$PRSZ)" >> $IMPL_FILE
                if test $des -eq 1; then
                    echo "#endif // 0" >> $IMPL_FILE
                fi
                for LD in nocoal coal coalshuf; do
                    for ST in nocoal coal coalshuf; do
                        gen=1
                        if test $LD == coal -a $ST == coalshuf; then
                            gen=0;
                        fi
                        if test $LD == coalshuf -a $ST == coal; then
                            gen=0;
                        fi
                        if test $gen == 1 -a $des == 0; then
                            echo "TEST_CUDA(aes_edrk, FT0, NULL, NULL, NULL, NULL, NULL, aes_encrypt_cuda_"$BTB"0_"$PRMT"_"$PRSZ$LD$ST", 1);" >> $ECB_FILE
                            echo "TEST_CUDA(aes_edrk, FT0, NULL, NULL, NULL, IV, NULL, aes_ctr_cuda_"$BTB"0_"$PRMT"_"$PRSZ$LD$ST", 1);" >> $CTR_FILE
                        fi
                    done
                done
            fi
        done
    done
done
# FT implementations
for TYPE in INT SEQ; do
    for NUM in 1 2 4; do
        for PRMT in C PRMT PRMT8AS32; do
            for PRSZ in 8 32; do
                gen=1
                if test $PRMT == PRMT8AS32; then
                    if test $PRSZ -eq 32; then
                        gen=0;
                    fi
                fi
                if test $gen -eq 1; then
                    echo "FUNC_AES_ALL_FT(FT_$TYPE,$NUM,$PRMT,$PRSZ)" >> $IMPL_FILE
                    for LD in nocoal coal coalshuf; do
                        for ST in nocoal coal coalshuf; do
                            gen=1
                            if test $LD == coal -a $ST == coalshuf; then
                                gen=0;
                            fi
                            if test $LD == coalshuf -a $ST == coal; then
                                gen=0;
                            fi
                            FT1=NULL
                            FT2=NULL
                            FT3=NULL
                            if test $NUM -ge 2; then
                                FT1=FT1
                            fi
                            if test $NUM -eq 4; then
                                FT2=FT2
                                FT3=FT3
                            fi
                            if test $gen == 1; then
                                echo "TEST_CUDA(aes_edrk, FT0, "$FT1", "$FT2", "$FT3", NULL, NULL, aes_encrypt_cuda_FT_"$TYPE$NUM"_"$PRMT"_"$PRSZ$LD$ST", 1);" >> $ECB_FILE
                                echo "TEST_CUDA(aes_edrk, FT0, "$FT1", "$FT2", "$FT3", IV, NULL, aes_ctr_cuda_FT_"$TYPE$NUM"_"$PRMT"_"$PRSZ$LD$ST", 1);" >> $CTR_FILE
                            fi
                        done
                    done
                fi
            done
        done
    done
done
echo "#endif // GPU_CREATE_ALL" >> $IMPL_FILE
