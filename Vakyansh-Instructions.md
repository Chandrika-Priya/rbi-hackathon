# Steps to run Sunbird Vakyansh

Create a <project_directory>

```
cd <project_directory>
```

Inside <project_directory>/container_vol do the following

- Create deployed_models/<language_name> 
- Create model_dict.json and add language configurations.
  Example (for Hindi):
  ```
  {
    "hi" : {
        "path": "/deployed_models/hindi/hindi.pt",
        "enablePunctuation" : false,
        "enableITN": false
    }
  }
  ```

Inside <project_directory>/container_vol/<language> download desired language models from https://storage.googleapis.com/asr-public-models/data-sources-deployment

Example (for Hindi):
```
wget https://storage.googleapis.com/asr-public-models/data-sources-deployment/hindi/dict.ltr.txt 
wget https://storage.googleapis.com/asr-public-models/data-sources-deployment/hindi/hindi.pt 
wget https://storage.googleapis.com/asr-public-models/data-sources-deployment/hindi/lexicon.lst
wget https://storage.googleapis.com/asr-public-models/data-sources-deployment/hindi/lm.binary
```

Once these are setup, you can run Sunbird Vakyansh using the Docker image available on gcr.io using the following command

```
docker run -m 80000m -itd -p 50051:50051 
--name speec_recognition_open_api 
-v <your_project_path>/container_vol:/opt/speech_recognition_open_api/deployed_models/ 
gcr.io/ekstepspeechrecognition/speech_recognition_model_api:3.0.4
```
