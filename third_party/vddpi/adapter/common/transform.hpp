#pragma once
// Existing training-only preprocessing, shared by both pilot paths.
static const int numeric_columns[]={0,2,4,10,11,12};
static const double medians[]={37.0,178356.0,10.0,0.0,0.0,40.0};
static const double means[]={38.58164675532078,189778.36651208502,10.0806793403151,1077.6488437087312,87.303829734959,40.437455852092995};
static const double scales[]={13.640223092304081,105548.3568808909,2.5726808256012395,7385.178676946586,402.9540308275458,12.347239075706955};
static const int categorical_columns[]={1,3,5,6,7,8,9,13};
static const char* categories_0[]={"?","Federal-gov","Local-gov","Never-worked","Private","Self-emp-inc","Self-emp-not-inc","State-gov","Without-pay"};
static const char* categories_1[]={"10th","11th","12th","1st-4th","5th-6th","7th-8th","9th","Assoc-acdm","Assoc-voc","Bachelors","Doctorate","HS-grad","Masters","Preschool","Prof-school","Some-college"};
static const char* categories_2[]={"Divorced","Married-AF-spouse","Married-civ-spouse","Married-spouse-absent","Never-married","Separated","Widowed"};
static const char* categories_3[]={"?","Adm-clerical","Armed-Forces","Craft-repair","Exec-managerial","Farming-fishing","Handlers-cleaners","Machine-op-inspct","Other-service","Priv-house-serv","Prof-specialty","Protective-serv","Sales","Tech-support","Transport-moving"};
static const char* categories_4[]={"Husband","Not-in-family","Other-relative","Own-child","Unmarried","Wife"};
static const char* categories_5[]={"Amer-Indian-Eskimo","Asian-Pac-Islander","Black","Other","White"};
static const char* categories_6[]={"Female","Male"};
static const char* categories_7[]={"?","Cambodia","Canada","China","Columbia","Cuba","Dominican-Republic","Ecuador","El-Salvador","England","France","Germany","Greece","Guatemala","Haiti","Holand-Netherlands","Honduras","Hong","Hungary","India","Iran","Ireland","Italy","Jamaica","Japan","Laos","Mexico","Nicaragua","Outlying-US(Guam-USVI-etc)","Peru","Philippines","Poland","Portugal","Puerto-Rico","Scotland","South","Taiwan","Thailand","Trinadad&Tobago","United-States","Vietnam","Yugoslavia"};
static const char** categories[]={categories_0,categories_1,categories_2,categories_3,categories_4,categories_5,categories_6,categories_7};
static const int category_lengths[]={9,16,7,15,6,5,2,42};
static const int dimension=108;
