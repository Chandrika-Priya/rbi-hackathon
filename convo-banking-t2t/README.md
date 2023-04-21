# Installation steps

Create python venv and install requirements
```
$ /usr/bin/python3 -m venv ~/envs/convo-comm-t2t
$ source ~/envs/convo-comm-t2t/bin/activate
$ pip install -r requirements.txt
```

Install fairseq pacakages
```
$ git clone https://github.com/pytorch/fairseq.git
$ pip install --editable ./fairseq
```

Install AI4Bharat's inference package
```
$ git clone https://github.com/AI4Bharat/indicTrans.git  
$ cp -r indicTrans/inference inference/
$ cp -r indicTrans/model_configs . 
$ pip install ./inference
```

Download AIBharath's indic2 models and update environmental variable
download both the models from below link in a path and export it to T2T_MODEL_PATH from [here](https://github.com/AI4Bharat/indicTrans#download-indictrans-models) and place it inside indic2models directory inside your project

Then do
```
$ export T2T_MODEL_PATH=<path_to_project>/indic2models
```

## Run the application
python api.py
