var worker=[];

new QWebChannel(qt.webChannelTransport, function(channel) {
    window.taskInfoBridge = channel.objects.taskInfoBridge;
    window.fileChooseBridge = channel.objects.fileChooseBridge;
    window.dataTurnBridge = channel.objects.dataTurnBridge;
    window.hashBridge = channel.objects.hashBridge;
    window.encryptBridge = channel.objects.encryptBridge;
    window.decryptBridge = channel.objects.decryptBridge;
});

let fileInput = document.querySelectorAll("input[type=\"button\"]");
////console.log(fileInput);
fileInput.forEach(element=>{
    element.addEventListener("click",(event)=>{
        ////console.log("click");
        window.fileChooseBridge.receive(element.id);
    })
})

function updateFile(data){
    document.getElementById(data.id+"Box").textContent = data.path;
    let type = data.id.replace("InputFile","");
    //console.log(type);
    if(type === "decrypt"){
        document.getElementById(type+"OutputText").value = "输出>>>"+data.path+".PLAIN";
    }else if(type === "encrypt"){
        document.getElementById(type+"OutputText").value = "输出>>>"+data.path+".CRYPT";
    }
    
}

function startUpdateTaskStatus(){
    setInterval(()=>{
        ////console.log("update")
        let tasks=[];
        for(let i=0;i<worker.length;++i){
            if(worker[i].status === "running"){
                tasks.push(worker[i]);
            }
        }
        if(tasks.length === 0){
            return;
        }
        //console.log(tasks);
        //(tasks)从后台调接口……
        window.taskInfoBridge.receive(tasks);
    },40);
}
document.addEventListener('DOMContentLoaded',()=>{
    startUpdateTaskStatus();
});
//only qt
function updateTaskStatus(data){
    //console.log(data);
    for(let i=0;i<data.length;++i){
        //console.log(data[i]);
        worker[data[i].id].status = data[i].status;
        worker[data[i].id].time = data[i].time;
        worker[data[i].id].result = data[i].result;
        let singleTaskProgress = document.getElementById("TaskProgress:"+data[i].id);
        let singleTaskTime = document.getElementById("TaskTime:"+data[i].id);
        let singleTaskTextOutput = document.getElementById("TextOutput:"+data[i].id);
        if(data[i].status === "success"){
            //console.log("TaskOutput:"+data[i].id);
            if(data[i].type === "hash"){
                singleTaskTextOutput.textContent = singleTaskTextOutput.textContent + data[i].result;
            }else if(data[i].type === "encrypt" || data[i].type === "decrypt"){
                singleTaskTextOutput.textContent = data[i].msg;
            }
            singleTaskProgress.value = 100;
            singleTaskTime.textContent = "耗时："+fmtTime(data[i].time);
        }else if(data[i].status === "running"){
            singleTaskProgress.value = data[i].progress;
            singleTaskTime.textContent = "预计剩余用时："+fmtTime(data[i].time);
        }else if(data[i].status === "fail"){
            singleTaskTextOutput.textContent = data[i].error;
            singleTaskProgress.value = 0;
            singleTaskTime.textContent = "耗时："+fmtTime(data[i].time);
        }
    }
}


function fmtTime(time){
    const list = [
        {"radix":1000,"unit":"微秒"},
        {"radix":1000,"unit":"毫秒"},
        {"radix":60,"unit":"秒"},
        {"radix":60,"unit":"分钟"},
        {"radix":24,"unit":"小时"},
        {"radix":30,"unit":"天"},
    ];
    let result = "";
    for(let i=0;i<list.length;++i){
        let nowPoint = time%list[i].radix;
        result = nowPoint+list[i].unit+result;
        time = Math.floor(time/list[i].radix);
        if(time === 0){
            break;
        }
    }
    return result;
    
}

function getOriInput(tag){
    let inputType = document.querySelector("input[name=\""+tag+"InputType\"]:checked").value;
    let midResult;
    if(inputType === "UTF_8"){
        let text = document.getElementById(tag+"InputText").value;
        midResult = {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":0,
            "value":text
        }
    }else if(inputType === "hex"){
        let text = document.getElementById(tag+"InputText").value;
        const charList = "0123456789ABCDEFabcdef"
        for(let i=0;i<text.length;++i){
            if(!charList.includes(text[i])){
                return  {
                    "status":false,
                    "error":"该模式下输入字符必须为"+charList
                }
            }
        }
        midResult = {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":2,
            "value":text
        }
    }else if(inputType === "base64"){
        let text = document.getElementById(tag+"InputText").value;
        let inputChar1 = document.getElementById(tag+"InputReplace+").value;
        let inputChar2 = document.getElementById(tag+"InputReplace/").value;
        let inputChar3 = document.getElementById(tag+"InputReplace=").value;
        if(inputChar1 === inputChar2 || inputChar1 === inputChar3 || inputChar2 === inputChar3){
            return  {
                "status":false,
                "error":"输入替换的字符不能相同"
            }
        }    
        let charList = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/="
        charList = charList.replace("+",inputChar1);
        charList = charList.replace("/",inputChar2);
        charList = charList.replace("=",inputChar3);
        for(let i=0;i<text.length;++i){
            if(!charList.includes(text[i])){
                return {
                    "status":false,
                    "error":"该模式下输入字符必须为"+charList
                }
            }
        }
        midResult =  {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":1,
            "value":text,
            "inputChar1":inputChar1,
            "inputChar2":inputChar2,
            "inputChar3":inputChar3
        }
    }else if(inputType === "file"){
        let path = document.getElementById(tag+"InputFileBox").textContent;
        document.getElementById(tag+"InputFileBox").textContent = "";
        //let file = document.getElementById(tag+"InputFileBox").files[0];
        //document.getElementById(tag+"InputFileBox").value = '';
        if(path === ""){
            return  {
                "status":false,
                "error":"未选择文件"
            }
        }
        //let path = window.electronAPI.getPath(file)
        midResult =  {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":3,
            "value":path
        }
    }else{
        midResult =  {
            "status":false,
            "error":"未知输入类型"
        }
    }
    if(!midResult.status){return midResult}
    let outputType = document.querySelector("input[name=\""+tag+"OutputType\"]:checked").value;
    if(outputType === "UTF_8"){
        midResult.outputType = outputType;
        midResult.outputTypeCode = 0;
    }else if(outputType === "hex"){
        midResult.outputType = outputType;
        midResult.outputTypeCode = 2;
        let isUpper = document.querySelector("input[name=\""+tag+"OutputUpper\"]:checked").value;
        if(isUpper === "true"){
            midResult.isUpper = true;
        }else{
            midResult.isUpper = false;
        }
    }else if(outputType === "base64"){
        midResult.outputType = outputType;
        midResult.outputTypeCode = 1;
        let outputChar1 = document.getElementById(tag+"OutputReplace+").value;
        let outputChar2 = document.getElementById(tag+"OutputReplace/").value;
        let outputChar3 = document.getElementById(tag+"OutputReplace=").value;
        if(outputChar1 === outputChar2 || outputChar1 === outputChar3 || outputChar2 === outputChar3){
            midResult =  {
                "status":false,
                "error":"输出替换的字符不能相同"
            }
        }
        midResult.outputChar1 = outputChar1;
        midResult.outputChar2 = outputChar2;
        midResult.outputChar3 = outputChar3;
    }else if(outputType === "file"){
        midResult.outputType = outputType;
        midResult.outputTypeCode = 3;
    }
    return midResult;
}

function addTaskTag(task){
    /**
     * task = {
     *      type: "hash" | "encrypt" | "decrypt",
     *      status: "waiting" | "running" | "success" | "fail",
     *      id: "",
     *      title: "",
     *      result: "",
     }
     */

    let taskListArea = document.getElementById("taskListArea");
    let signleTaskField = document.createElement("div");
    signleTaskField.className = "singleTaskField";
    signleTaskField.id = "taskTag:"+task.id;
    signleTaskField.status = task.status;
     let singeTaskDetailField = document.createElement("div");
     singeTaskDetailField.className = "singeTaskDetailField";
      let singleTaskIconField = document.createElement("div");
      singleTaskIconField.className = "singleTaskIconField";
       let singleTaskIcon = document.createElement("img");
       singleTaskIcon.className = "singleTaskIcon";
       if(task.type === "hash"){
           singleTaskIcon.src = "resource/fileHash.png";
       }else if(task.type === "encrypt"){
           singleTaskIcon.src = "resource/fileLock.png";
       }else if(task.type === "decrypt"){
           singleTaskIcon.src = "resource/fileUnlock.png";
       }
       singleTaskIconField.appendChild(singleTaskIcon);
       singeTaskDetailField.appendChild(singleTaskIconField);
      let singleTaskText = document.createElement("div");
      singleTaskText.className = "singleTaskText";
      singleTaskText.id = "taskText:"+task.id;
      singeTaskDetailField.appendChild(singleTaskText);
       //添加内容

       let singleTaskInput = document.createElement("div");
       //console.log(task.title);
       let taskList = task.title.split(">");
       singleTaskInput.textContent = taskList[0];
       singleTaskInput.className = "singleTaskTextInput";
       singleTaskInput.id = "TaskTextInput:"+task.id;
       singleTaskText.appendChild(singleTaskInput);
       let singleTaskConfig = document.createElement("div");
       singleTaskConfig.textContent = taskList[1];
       singleTaskConfig.className = "singleTaskTextConfig";
       singleTaskConfig.id = "TaskTextConfig:"+task.id;
       singleTaskText.appendChild(singleTaskConfig);
       let singleTaskOutput = document.createElement("div");
       singleTaskOutput.textContent = taskList[2];
       singleTaskOutput.className = "singleTaskTextOutput";
       singleTaskOutput.id = "TextOutput:"+task.id;
       singleTaskText.appendChild(singleTaskOutput);
       let singleTaskTime = document.createElement("div");
       singleTaskTime.textContent = "耗时";
       singleTaskTime.className = "singleTaskTime";
       singleTaskTime.id = "TaskTime:"+task.id;
       singleTaskText.appendChild(singleTaskTime);

      signleTaskField.appendChild(singeTaskDetailField);
     let singleTaskProgressField = document.createElement("div");
     singleTaskProgressField.className = "singleTaskProgressField";
      let singleTaskProgress = document.createElement("progress");
      singleTaskProgress.className = "singleTaskProgress";
      //singleTaskProgress.value = 0;
      singleTaskProgress.id = "TaskProgress:"+task.id;
      singleTaskProgress.max = 100;
      singleTaskProgressField.appendChild(singleTaskProgress);
    signleTaskField.appendChild(singleTaskProgressField);
    taskListArea.appendChild(signleTaskField);
}


//全局标签切换
var functionChoice = document.querySelectorAll('[function-choice]');
////console.log(functionChoice);
var functionChoiceStage=new Map();
functionChoiceStage.set("dataChoice",true);
functionChoiceStage.set("hashChoice",false);
functionChoiceStage.set("encryptChoice",false);
functionChoiceStage.set("decryptChoice",false);
functionChoiceStage.set("taskChoice",false);
functionChoiceStage.set("aboutChoice",false);


functionChoice.forEach(element => {
    element.addEventListener("click",(event) => {
        functionChoiceStage.forEach((value, key, map) => {
            map.set(key,false);
        })
        var target = event.target.closest('[function-choice]');
        functionChoiceStage.set(target.id,true);

        functionChoiceStage.forEach((value,key,map) => {
            let element = document.getElementById(key);
            ////console.log(key.replace("Choice","Area"));
            let area = document.getElementById(key.replace("Choice","Area"));
            if(value){
                element.className="menuChoiceActive"
                area.hidden = false;
            }else{
                element.className="menuChoice"
                area.hidden = true;
            }
        })
        
    })
})
//结束

//数据转换逻辑
var dataInputTypes = document.getElementsByName("dataInputType");
dataInputTypes.forEach(element => {
    element.addEventListener("change", (event) => {
        let inputReplaceChar = document.getElementById("dataReplaceCharField");
        let value = event.target.value;
        if (value === "base64") {
            inputReplaceChar.hidden = false;
        }else{
            inputReplaceChar.hidden = true;
        }
    })
})

var dataButton = document.getElementById("dataButton");
dataButton.addEventListener("click", (event) => {
    let valueConfig = getOriInput("data");
    //console.log(valueConfig);
    if(!valueConfig.status){
        alert(valueConfig.error);
        return;
    }else if(valueConfig.value === ""){
        alert("请输入数据");
        return;
    }
    //dataTurn(valueConfig);
    window.dataTurnBridge.receive(JSON.stringify(valueConfig));
});

//only qt
function setDataResult(data){
    //console.log(data);
    let dataSpendTimeField = document.getElementById("dataSpendTimeField");
    if(data.status === false){
        alert(data.error);
        dataSpendTimeField.textContent = "耗时";
        return;
    }
    let dataOutputText = document.getElementById("dataOutputText");
    dataOutputText.value = data.result;
    dataSpendTimeField.textContent = "耗时:"+fmtTime(data.time);
}

var dataOutputTypes = document.getElementsByName("dataOutputType");

dataOutputTypes.forEach(element => {
    element.addEventListener("change", (event) => {
        let outputReplaceChar = document.getElementById("dataOutputReplaceCharField");
        let outputIsUpper = document.getElementById("dataOutputIsUpperField");
        let value = event.target.value;
        if (value === "base64") {
            outputReplaceChar.hidden = false;
            outputIsUpper.hidden = true;
        }else if(value === "hex"){
            outputReplaceChar.hidden = true;
            outputIsUpper.hidden = false;
        }else{
            outputReplaceChar.hidden = true;
            outputIsUpper.hidden = true;
        }
    })
})
//结束

var hashInputTypes = document.getElementsByName("hashInputType");

hashInputTypes.forEach(element => {
    element.addEventListener("change", (event) => {
        var textInputField = document.getElementById("hashInputTextField");
        var fileInput = document.getElementById("hashInputFileField");
        var textInput = document.getElementById("hashTextInput");
        var inputReplaceChar = document.getElementById("hashInputReplaceCharField");
        var value = event.target.value;
        if (value === "file") {
            inputReplaceChar.hidden = true;
            textInputField.hidden = true;
            fileInput.hidden = false;
        }else if(value === "base64"){
            inputReplaceChar.hidden = false;
            textInputField.hidden = false;
            fileInput.hidden = true;
        }else if(value === "hex"){
            inputReplaceChar.hidden = true;
            textInputField.hidden = false;
            fileInput.hidden = true;
        }else{
            inputReplaceChar.hidden = true;
            textInputField.hidden = false;
            fileInput.hidden = true;
        }
    })
});

var hashOutputTypes = document.getElementsByName("hashOutputType");

hashOutputTypes.forEach(element => {
    element.addEventListener("change", (event) => {
        let outputReplaceChar = document.getElementById("hashOutputReplaceCharField");
        let outputIsUpper = document.getElementById("hashOutputIsUpperField");
        let value = event.target.value;
        if (value === "base64") {
            outputReplaceChar.hidden = false;
            outputIsUpper.hidden = true;
        }else{
            outputReplaceChar.hidden = true;
            outputIsUpper.hidden = false;
        }
    })
})

var hashButton = document.getElementById("hashButton");
hashButton.addEventListener("click",(event) =>{
    let valueConfig = getOriInput("hash");
    //console.log(valueConfig);
    if(!valueConfig.status){
        alert(valueConfig.error);
        return;
    }
    let hashType = document.getElementById("hashMethodChoice").value;
    //console.log(hashType);
    //(valueConfig,hashType)从后台调用接口……
    window.hashBridge.receive(JSON.stringify(valueConfig),hashType);

})

//only qt
function setHashResult(data){
    //console.log(data);
    let SpendTimeField = document.getElementById("hashSpendTimeField");
    if(data.status === false){
        alert(data.error);
        dataSpendTimeField.textContent = "耗时";
        return;
    }
    let OutputText = document.getElementById("hashOutputText");
    if(data.type === "text"){
        OutputText.value = data.result;
        SpendTimeField.textContent = "耗时:"+fmtTime(data.time);
    }else if(data.type === "file"){
        let msg = data.file+">"+data.hash+">"+data.output;
        OutputText.value = msg+"已添加至任务队列";
        let task = {
            type: "hash",
            status: "running",
            id: parseInt(data.id),
            output: data.output,
            outputCode: data.outputCode,
            title: msg,
            result: "",
            process: "",
            time: 0,
            outputChar1:data.outputChar1,
            outputChar2: data.outputChar2,
            outputChar3: data.outputChar3,
            isUpper: data.isUpper
        }
        //console.log(task);
        worker.push(task);
        addTaskTag(task);
    }

}

//结束

//加密区域逻辑
//控制明文输入时 base64显示替换字符 file隐藏输入框 其他隐藏文件输入
var encryptInputTypes = document.getElementsByName("encryptInputType");
encryptInputTypes.forEach(element => {
    element.addEventListener("change", (event) => {
        var textInputField = document.getElementById("encryptInputTextField");
        var fileInput = document.getElementById("encryptInputFileField");
        var inputReplaceChar = document.getElementById("encryptInputReplaceCharField");
        
        let encryptOutputUTF_8 = document.getElementById("encryptOutputUTF_8");
        let encryptOutputHex = document.getElementById("encryptOutputHex");
        let encryptOutputBase64 = document.getElementById("encryptOutputBase64");
        let encryptOutputFile = document.getElementById("encryptOutputFile");
        let encryptOutputTypeChoice = document.getElementById("encryptOutputTypeChoice");
        let encryptOutputText = document.getElementById("encryptOutputText");
        let encryptWithConfigField = document.getElementById("encryptWithConfigField");
        let encryptInputFileBox = document.getElementById("encryptInputFileBox");
        var value = event.target.value;
        if (value === "file") {
            inputReplaceChar.hidden = true;
            textInputField.hidden = true;
            fileInput.hidden = false;

            encryptOutputUTF_8.disabled = true;
            encryptOutputHex.disabled = true;
            encryptOutputBase64.disabled = true;
            encryptOutputFile.disabled = false;

            encryptOutputFile.checked = true;
            encryptOutputTypeChoice.hidden = true;

            encryptOutputText.rows = 1;
            encryptOutputText.placeholder = "输出文件路径";
            encryptOutputText.readOnly = "";

            encryptWithConfigField.hidden = false;
        }else if(value === "base64"){
            encryptOutputUTF_8.disabled = false;
            encryptOutputHex.disabled = false;
            encryptOutputBase64.disabled = false;
            encryptOutputFile.disabled = true;

            encryptOutputFile.checked = false;
            encryptOutputHex.checked = true;
            encryptOutputTypeChoice.hidden = false;

            inputReplaceChar.hidden = false;
            textInputField.hidden = false;
            fileInput.hidden = true;

            encryptOutputText.value = ""
            encryptOutputText.rows = 10;
            encryptOutputText.placeholder = "密文输出";
            encryptOutputText.readOnly = true;

            encryptWithConfigField.hidden = true;

            encryptInputFileBox.value = '';
            
        }else{
            encryptOutputUTF_8.disabled = false;
            encryptOutputHex.disabled = false;
            encryptOutputBase64.disabled = false;
            encryptOutputFile.disabled = true;

            encryptOutputFile.checked = false;
            encryptOutputHex.checked = true;
            encryptOutputTypeChoice.hidden = false;

            inputReplaceChar.hidden = true;
            textInputField.hidden = false;
            fileInput.hidden = true;

            encryptOutputText.value = ""
            encryptOutputText.rows = 10;
            encryptOutputText.placeholder = "密文输出";
            encryptOutputText.readOnly = true;

            encryptWithConfigField.hidden = true;
            encryptInputFileBox.value = '';
        }
    })
})

var encryptInputFileBox = document.getElementById("encryptInputFileField");
encryptInputFileBox.addEventListener("change",(event)=>{
    let encryptOutputText = document.getElementById("encryptOutputText");
    let path = window.electronAPI.getPath(event.target.files[0]);
    encryptOutputText.value = "输出>>>"+path+".CRYPT";
})

//控制base64显示替换字符 hex显示是否大写 其他隐藏
var encryptOutputTypes = document.getElementsByName("encryptOutputType");
encryptOutputTypes.forEach(element => {
    element.addEventListener("change", (event) => {
        let outputReplaceChar = document.getElementById("encryptOutputReplaceCharField");
        let outputIsUpper = document.getElementById("encryptOutputIsUpperField");
        let value = event.target.value;
        if (value === "base64") {
            outputReplaceChar.hidden = false;
            outputIsUpper.hidden = true;
        }else if(value === "hex"){
            outputReplaceChar.hidden = true;
            outputIsUpper.hidden = false;
        }else{
            outputReplaceChar.hidden = true;
            outputIsUpper.hidden = true;
        }
    })
})

//根据算法控制可选控制块大小和密钥长度
var encryptMethodChoice = document.getElementById("encryptMethodChoice");
encryptMethodChoice.addEventListener("change", (event) => {
    //console.log(event.target.value);
    let encryptBlockSize = document.getElementById("encryptInputBlockSize");
    let encryptKeySize = document.getElementById("encryptInputKeySize");
    if(event.target.value === "AES"){
        encryptBlockSize.min=16;
        encryptBlockSize.max=16;
        encryptBlockSize.value=16;
        
        encryptKeySize.min=16;
        encryptKeySize.max=32;
        encryptKeySize.value=16;
        encryptKeySize.step=8;
    }else if(event.target.value === "SM4"){
        encryptBlockSize.min=16;
        encryptBlockSize.max=16;
        encryptBlockSize.value=16;

        encryptKeySize.min=16;
        encryptKeySize.max=16;
        encryptKeySize.value=16;
        encryptKeySize.step=0;
    }
})

//根据选择展示填充算法
var encryptIsPadding = document.getElementsByName("encryptIsPadding");
encryptIsPadding.forEach(element => {
    element.addEventListener("change", (event) =>{
        let paddingChoiceField = document.getElementById("encryptPaddingChoiceField");
        if(event.target.value === "true"){
            paddingChoiceField.hidden = false;
        }else{
            paddingChoiceField.hidden = true;
        }
    })
})

let encryptButton = document.getElementById("encryptButton");
encryptButton.addEventListener("click",(event)=>{
    let valueConfig = getOriInput("encrypt");
    if(!valueConfig.status){
        alert(valueConfig.error);
        return;
    }else if(valueConfig.value === ""){
        alert("请输入明文");
        return;
    }
    //console.log(valueConfig);

    let encryptMethodChoice = document.getElementById("encryptMethodChoice");
    let encryptInputBlockSize = document.getElementById("encryptInputBlockSize");
    let encryptInputKeySize = document.getElementById("encryptInputKeySize");
    let encryptModeChoice = document.getElementById("encryptModeChoice");
    let encryptIsPaddingChoice = document.querySelector("input[name=\"encryptIsPadding\"]:checked");
    let encryptPaddingChoice = document.getElementById("encryptPaddingChoice");
    let encryptWithConfigChoice = document.getElementById("encryptWithConfig");
    
    let encryptAlgorithm = encryptMethodChoice.value;
    let encryptBlockSize = encryptInputBlockSize.value;
    let encryptKeySize = encryptInputKeySize.value;
    let encryptMode = encryptModeChoice.value;
    let encryptIsPadding = encryptIsPaddingChoice.value==="true"?true:false;
    let encryptPadding = encryptPaddingChoice.value;
    let encryptWithConfig = encryptWithConfigChoice.checked;
    let encryptConfig = {
        algorithm: encryptAlgorithm,
        blockSize: parseInt(encryptBlockSize),
        keySize: parseInt(encryptKeySize),
        mode: encryptMode,
        isPadding: encryptIsPadding,
        padding: encryptPadding,
        withConfig: encryptWithConfig
    }
    //console.log(encryptConfig);
    let tag = "encryptKey";
    let inputType = document.querySelector("input[name=\""+tag+"InputType\"]:checked").value;
    let midResult;
    if(inputType === "UTF_8"){
        let text = document.getElementById(tag+"InputText").value;
        midResult = {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":0,
            "value":text
        }
    }else if(inputType === "hex"){
        let text = document.getElementById(tag+"InputText").value;
        const charList = "0123456789ABCDEFabcdef"
        for(let i=0;i<text.length;++i){
            if(!charList.includes(text[i])){
                midResult =  {
                    "status":false,
                    "error":"该模式下输入字符必须为"+charList
                }
            }
        }
        midResult = {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":2,
            "value":text
        }
    }else if(inputType === "base64"){
        let text = document.getElementById(tag+"InputText").value;
        let inputChar1 = document.getElementById(tag+"InputReplace+").value;
        let inputChar2 = document.getElementById(tag+"InputReplace/").value;
        let inputChar3 = document.getElementById(tag+"InputReplace=").value;
        if(inputChar1 === inputChar2 || inputChar1 === inputChar3 || inputChar2 === inputChar3){
            midResult =  {
                "status":false,
                "error":"输入替换的字符不能相同"
            }
        }    
        let charList = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/="
        charList = charList.replace("+",inputChar1);
        charList = charList.replace("/",inputChar2);
        charList = charList.replace("=",inputChar3);
        for(let i=0;i<text.length;++i){
            if(!charList.includes(text[i])){
                midResult = {
                    "status":false,
                    "error":"该模式下输入字符必须为"+charList
                }
            }
        }
        midResult =  {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":1,
            "value":text,
            "inputChar1":inputChar1,
            "inputChar2":inputChar2,
            "inputChar3":inputChar3
        }
    }else if(inputType === "file"){
        let file = document.getElementById(tag+"InputFileBox").files[0];
        document.getElementById(tag+"InputFileBox").value = '';
        if(file === undefined){
            midResult =  {
                "status":false,
                "error":"未选择文件"
            }
        }
        let path = window.electronAPI.getPath(file)
        midResult =  {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":3,
            "value":path
        }
    }else{
        midResult =  {
            "status":false,
            "error":"未知输入类型"
        }
    }
    if(!midResult.status){
        alert(midResult.error);
        return;
    }else if(midResult.value === ""){
        alert("密钥输入不能为空");
        return;
    }
    let encryptKeyConfig = midResult;
    //console.log(encryptKeyConfig);
    console.log(valueConfig);
    console.log(encryptConfig);
    console.log(encryptKeyConfig);
    window.encryptBridge.receive(valueConfig,encryptConfig,encryptKeyConfig)
})

//only qt
function setEncryptResult(data){
    if(!data.status){
        alert(data.error);
        return;
    }else{
        let OutputText = document.getElementById("encryptOutputText");
        if(data.type === "text"){
            OutputText.value = data.result;
            let encryptSpendTimeField = document.getElementById("encryptSpendTimeField");
            encryptSpendTimeField.textContent = "耗时:"+fmtTime(data.time);
        }else if(data.type === "file"){
            let msg = data.inputFile+">"+data.cryption+">"+data.outputFile;
            OutputText.value = msg+"已添加至任务队列";
            let task = {
                type: "encrypt",
                status: "running",
                id: parseInt(data.id),
                inputFile: data.inputFile,
                outputFile: data.outputFile,
                title: msg,
                process: "",
                time: 0
            }
            //console.log(task);
            worker.push(task);
            addTaskTag(task);
        }

    }
}

//根据模式限制填充算法
var encryptModeChoice = document.getElementById("encryptModeChoice");
encryptModeChoice.addEventListener("change", (event) => {
    let encryptIsPaddingTrue = document.getElementById("encryptIsPaddingTrue");
    let encryptIsPaddingFalse = document.getElementById("encryptIsPaddingFalse");
    let paddingChoiceField = document.getElementById("encryptPaddingChoiceField");
    let value = event.target.value;
    if(value === "ECB" || value === "CBC"){
        encryptIsPaddingTrue.checked = true;
        encryptIsPaddingFalse.disabled = true;
        paddingChoiceField.hidden = false;
    }else{
        encryptIsPaddingFalse.disabled = false;
        paddingChoiceField.hidden = false;
    }
})

//控制密钥输入时 base64显示替换字符 其他隐藏
var encryptKeyInputType = document.getElementsByName("encryptKeyInputType");
encryptKeyInputType.forEach(element => {
    element.addEventListener("change",(event) => {
        let encryptKeyInputReplaceCharField = document.getElementById("encryptKeyInputReplaceCharField");
        let value = event.target.value;
        if(value === "base64"){
            encryptKeyInputReplaceCharField.hidden = false;
        }else{
            encryptKeyInputReplaceCharField.hidden = true;
        }
    })
})

//结束

//解密区域逻辑
//控制明文输入时 base64显示替换字符 file隐藏输入框 其他隐藏文件输入
var decryptInputTypes = document.getElementsByName("decryptInputType");
decryptInputTypes.forEach(element => {
    element.addEventListener("change", (event) => {
        var textInputField = document.getElementById("decryptInputTextField");
        var fileInput = document.getElementById("decryptInputFileField");
        var inputReplaceChar = document.getElementById("decryptInputReplaceCharField");
        
        let decryptOutputUTF_8 = document.getElementById("decryptOutputUTF_8");
        let decryptOutputHex = document.getElementById("decryptOutputHex");
        let decryptOutputBase64 = document.getElementById("decryptOutputBase64");
        let decryptOutputFile = document.getElementById("decryptOutputFile");
        let decryptOutputTypeChoice = document.getElementById("decryptOutputTypeChoice");
        let decryptOutputText = document.getElementById("decryptOutputText");
        let decryptWithConfigField = document.getElementById("decryptWithConfigField");
        let decryptInputFileBox = document.getElementById("decryptInputFileBox");
        var value = event.target.value;
        if (value === "file") {
            inputReplaceChar.hidden = true;
            textInputField.hidden = true;
            fileInput.hidden = false;

            decryptOutputUTF_8.disabled = true;
            decryptOutputHex.disabled = true;
            decryptOutputBase64.disabled = true;
            decryptOutputFile.disabled = false;

            decryptOutputFile.checked = true;
            decryptOutputTypeChoice.hidden = true;

            decryptOutputText.rows = 1;
            decryptOutputText.placeholder = "输出文件路径";
            decryptOutputText.readOnly = "";

            decryptWithConfigField.hidden = false;
        }else if(value === "base64"){
            inputReplaceChar.hidden = false;
            textInputField.hidden = false;
            fileInput.hidden = true;

            decryptOutputUTF_8.disabled = false;
            decryptOutputHex.disabled = false;
            decryptOutputBase64.disabled = false;
            decryptOutputFile.disabled = true;

            decryptOutputFile.checked = false;
            decryptOutputHex.checked = true;
            decryptOutputTypeChoice.hidden = false;

            inputReplaceChar.hidden = false;
            textInputField.hidden = false;
            fileInput.hidden = true;

            decryptOutputText.value = ""
            decryptOutputText.rows = 10;
            decryptOutputText.placeholder = "密文输出";
            decryptOutputText.readOnly = true;

            decryptWithConfigField.hidden = true;

            decryptInputFileBox.value = '';
        }else{
            inputReplaceChar.hidden = true;
            textInputField.hidden = false;
            fileInput.hidden = true;
            
            decryptOutputUTF_8.disabled = false;
            decryptOutputHex.disabled = false;
            decryptOutputBase64.disabled = false;
            decryptOutputFile.disabled = true;

            decryptOutputFile.checked = false;
            decryptOutputHex.checked = true;
            decryptOutputTypeChoice.hidden = false;

            decryptOutputText.value = ""
            decryptOutputText.rows = 10;
            decryptOutputText.placeholder = "密文输出";
            decryptOutputText.readOnly = true;

            decryptWithConfigField.hidden = true;

            decryptInputFileBox.value = '';
        }
    })
})

var decryptInputFileBox = document.getElementById("decryptInputFileField");
decryptInputFileBox.addEventListener("change",(event)=>{
    let decryptOutputText = document.getElementById("decryptOutputText");
    let path = window.electronAPI.getPath(event.target.files[0]);
    decryptOutputText.value = "输出>>>"+path+".PLAIN";
})

//控制base64显示替换字符 hex显示是否大写 其他隐藏
var decryptOutputTypes = document.getElementsByName("decryptOutputType");
decryptOutputTypes.forEach(element => {
    element.addEventListener("change", (event) => {
        let outputReplaceChar = document.getElementById("decryptOutputReplaceCharField");
        let outputIsUpper = document.getElementById("decryptOutputIsUpperField");
        let value = event.target.value;
        if (value === "base64") {
            outputReplaceChar.hidden = false;
            outputIsUpper.hidden = true;
        }else if(value === "hex"){
            outputReplaceChar.hidden = true;
            outputIsUpper.hidden = false;
        }else{
            outputReplaceChar.hidden = true;
            outputIsUpper.hidden = true;
        }
    })
})

//根据算法控制可选控制块大小和密钥长度
var decryptMethodChoice = document.getElementById("decryptMethodChoice");
decryptMethodChoice.addEventListener("change", (event) => {
    ////console.log(event.target.value);
    let decryptBlockSize = document.getElementById("decryptInputBlockSize");
    let decryptKeySize = document.getElementById("decryptInputKeySize");
    if(event.target.value === "AES"){
        decryptBlockSize.min=16;
        decryptBlockSize.max=16;
        decryptBlockSize.value=16;
        
        decryptKeySize.min=16;
        decryptKeySize.max=32;
        decryptKeySize.value=16;
        decryptKeySize.step=8;
    }else if(event.target.value === "SM4"){
        decryptBlockSize.min=16;
        decryptBlockSize.max=16;
        decryptBlockSize.value=16;

        decryptKeySize.min=16;
        decryptKeySize.max=16;
        decryptKeySize.value=16;
    }
})

//根据选择展示填充算法
var decryptIsPadding = document.getElementsByName("decryptIsPadding");
decryptIsPadding.forEach(element => {
    element.addEventListener("change", (event) =>{
        let paddingChoiceField = document.getElementById("decryptPaddingChoiceField");
        if(event.target.value === "true"){
            paddingChoiceField.hidden = false;
        }else{
            paddingChoiceField.hidden = true;
        }
    })
})

//根据模式限制填充算法
var decryptModeChoice = document.getElementById("decryptModeChoice");
decryptModeChoice.addEventListener("change", (event) => {
    let decryptIsPaddingTrue = document.getElementById("decryptIsPaddingTrue");
    let decryptIsPaddingFalse = document.getElementById("decryptIsPaddingFalse");
    let paddingChoiceField = document.getElementById("decryptPaddingChoiceField");
    let value = event.target.value;
    if(value === "ECB" || value === "CBC"){
        decryptIsPaddingTrue.checked = true;
        decryptIsPaddingFalse.disabled = true;
        paddingChoiceField.hidden = false;
    }else{
        decryptIsPaddingFalse.disabled = false;
        paddingChoiceField.hidden = false;
    }
})

//控制密钥输入时 base64显示替换字符 其他隐藏
var decryptKeyInputType = document.getElementsByName("decryptKeyInputType");
decryptKeyInputType.forEach(element => {
    element.addEventListener("change",(event) => {
        let decryptKeyInputReplaceCharField = document.getElementById("decryptKeyInputReplaceCharField");
        let value = event.target.value;
        if(value === "base64"){
            decryptKeyInputReplaceCharField.hidden = false;
        }else{
            decryptKeyInputReplaceCharField.hidden = true;
        }
    })
})

let decryptButton = document.getElementById("decryptButton");
decryptButton.addEventListener("click",(event)=>{
    let valueConfig = getOriInput("decrypt");
    if(!valueConfig.status){
        alert(valueConfig.error);
        return;
    }else if(valueConfig.value === ""){
        alert("请输入密文");
        return;
    }
    //console.log(valueConfig);

    let decryptMethodChoice = document.getElementById("decryptMethodChoice");
    let decryptInputBlockSize = document.getElementById("decryptInputBlockSize");
    let decryptInputKeySize = document.getElementById("decryptInputKeySize");
    let decryptModeChoice = document.getElementById("decryptModeChoice");
    let decryptIsPaddingChoice = document.querySelector("input[name=\"decryptIsPadding\"]:checked");
    let decryptPaddingChoice = document.getElementById("decryptPaddingChoice");
    let decryptWithConfigChoice = document.getElementById("decryptWithConfig");
    
    let decryptAlgorithm = decryptMethodChoice.value;
    let decryptBlockSize = decryptInputBlockSize.value;
    let decryptKeySize = decryptInputKeySize.value;
    let decryptMode = decryptModeChoice.value;
    let decryptIsPadding = decryptIsPaddingChoice.value==="true"?true:false;
    let decryptPadding = decryptPaddingChoice.value;
    let decryptWithConfig = decryptWithConfigChoice.checked;
    let decryptConfig = {
        algorithm: decryptAlgorithm,
        blockSize: parseInt(decryptBlockSize),
        keySize: parseInt(decryptKeySize),
        mode: decryptMode,
        isPadding: decryptIsPadding,
        padding: decryptPadding,
        withConfig: decryptWithConfig
    }
    //console.log(decryptConfig);
    let tag = "decryptKey";
    let inputType = document.querySelector("input[name=\""+tag+"InputType\"]:checked").value;
    let midResult;
    if(inputType === "UTF_8"){
        let text = document.getElementById(tag+"InputText").value;
        midResult = {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":0,
            "value":text
        }
    }else if(inputType === "hex"){
        let text = document.getElementById(tag+"InputText").value;
        const charList = "0123456789ABCDEFabcdef"
        for(let i=0;i<text.length;++i){
            if(!charList.includes(text[i])){
                midResult =  {
                    "status":false,
                    "error":"该模式下输入字符必须为"+charList
                }
            }
        }
        midResult = {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":2,
            "value":text
        }
    }else if(inputType === "base64"){
        let text = document.getElementById(tag+"InputText").value;
        let inputChar1 = document.getElementById(tag+"InputReplace+").value;
        let inputChar2 = document.getElementById(tag+"InputReplace/").value;
        let inputChar3 = document.getElementById(tag+"InputReplace=").value;
        if(inputChar1 === inputChar2 || inputChar1 === inputChar3 || inputChar2 === inputChar3){
            midResult =  {
                "status":false,
                "error":"输入替换的字符不能相同"
            }
        }    
        let charList = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/="
        charList = charList.replace("+",inputChar1);
        charList = charList.replace("/",inputChar2);
        charList = charList.replace("=",inputChar3);
        for(let i=0;i<text.length;++i){
            if(!charList.includes(text[i])){
                midResult = {
                    "status":false,
                    "error":"该模式下输入字符必须为"+charList
                }
            }
        }
        midResult =  {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":1,
            "value":text,
            "inputChar1":inputChar1,
            "inputChar2":inputChar2,
            "inputChar3":inputChar3
        }
    }else if(inputType === "file"){
        let file = document.getElementById(tag+"InputFileBox").files[0];
        document.getElementById(tag+"InputFileBox").value = '';
        if(file === undefined){
            midResult =  {
                "status":false,
                "error":"未选择文件"
            }
        }
        let path = window.electronAPI.getPath(file)
        midResult =  {
            "status":true,
            "inputType":inputType,
            "inputTypeCode":3,
            "value":path
        }
    }else{
        midResult =  {
            "status":false,
            "error":"未知输入类型"
        }
    }
    if(!midResult.status){
        alert(midResult.error);
        return;
    }else if(midResult.value === ""){
        alert("密钥不能为空");
        return;
    }
    let decryptKeyConfig = midResult;
    window.decryptBridge.receive(valueConfig,decryptConfig,decryptKeyConfig)
})
function setDecryptResult(data){
    if(!data.status){
        alert(data.error);
        return;
    }else{
        let OutputText = document.getElementById("decryptOutputText");
        if(data.type === "text"){
            OutputText.value = data.result;
            let decryptSpendTimeField = document.getElementById("decryptSpendTimeField");
            decryptSpendTimeField.textContent = "耗时:"+fmtTime(data.time);
        }else if(data.type === "file"){
            let msg = data.inputFile+">"+data.cryption+">"+data.outputFile;
            OutputText.value = msg+"已添加至任务队列";
            let task = {
                type: "decrypt",
                status: "running",
                id: parseInt(data.id),
                inputFile: data.inputFile,
                outputFile: data.outputFile,
                title: msg,
                process: "",
                time: 0
            }
            //console.log(task);
            worker.push(task);
            addTaskTag(task);
        }
        
    }
}
//结束