function fmtTime(time){
    const list = [
        {"radix":1000,"unit":"us"},
        {"radix":1000,"unit":"ms"},
        {"radix":60,"unit":"s"},
        {"radix":60,"unit":"min"},
        {"radix":24,"unit":"h"},
        {"radix":30,"unit":"d"},
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

var dialogId = [];
function getSpaceDialogId(){
    dialogId.sort((a, b) => a - b);
    let id = 0;
    for(let i=0;i<dialogId.length;++i){
        if(dialogId[i] !== id){
            break;
        }
        ++id;
    }
    dialogId.push(id);
    return id;
}
//弹窗显示
function showing(type,msg){
    let msgDialog = document.getElementById("msg_dialog");
    let msgArea = document.createElement("div");
    msgArea.className = "msg_area";
    let msgTitleField = document.createElement("div");
    msgTitleField.className = "msg_title_field";
    let msgTitleEmoji = document.createElement("a");
    let msgTitle = document.createElement("div");
    msgTitle.className = "msg_title";
    msgTitleEmoji.className = "msg_title_emoji";
    if(type===0){
        msgTitleEmoji.innerHTML = "✔️";
        msgTitle.innerHTML = "成功";
    }else if(type===1){
        msgTitleEmoji.innerHTML = "❌";
        msgTitle.innerHTML = "失败";
    }else if(type===2){
        msgTitleEmoji.innerHTML = "⚠️";
        msgTitle.innerHTML = "警告";
    }
    let msgClose = document.createElement("div");
    msgClose.className = "msg_close";
    msgClose.innerHTML = "×";
    msgArea.appendChild(msgTitleField);
    msgTitleField.appendChild(msgTitleEmoji);
    msgTitleField.appendChild(msgTitle);
    msgTitleField.appendChild(msgClose);
    let msgContent = document.createElement("div");
    msgContent.className = "msg_content";
    msgContent.innerHTML = msg;
    msgArea.appendChild(msgContent);
    msgDialog.appendChild(msgArea);
    msgClose.addEventListener("click",(event)=>{
       msgDialog.removeChild(msgArea);
    })
    setTimeout(()=>{
        if(msgDialog.children.length > 0){
            msgDialog.removeChild(msgArea);
        }   
    },1500)
    msgDialog.show();
}

//添加剪贴板操作
function copyToClipboard(text) {
    window.copyBridge.receive(text);
}
function qtCopyBack(result){
    showing(0,result.msg);
}
var taskInfo=[];

//页标签切换
let sidebar = document.getElementById("sidebar")
let main = document.getElementById("main")
sidebar.childNodes.forEach((self)=>{
    self.addEventListener("click",(event)=>{
        let target = event.target;
        sidebar.childNodes.forEach((element)=>{
            //console.log(element);
            if(element.className === "sidebar_item_active"){
                element.className = "sidebar_item";
            }
        })
        main.childNodes.forEach((element)=>{
            if(element.className === "main_box"){
                element.hidden = true;
            }
        })
        while(target.className !== "sidebar_item"){
            target = target.parentElement;
        }
        target.className = "sidebar_item_active";
        let this_area = document.getElementById(target.id.split("_")[0]+"_area");
        this_area.hidden = false;        
    })
})

function breakRegion(region){
    region = region.replace("[","");
    region = region.replace("]",",");
    let list = [];
    region.split(",").forEach(str=>{
        if(str === "$"){
            list.push(9007199254740991);
        }else{
            list.push(parseInt(str));
        }
    })
    return list;
}

document.addEventListener("DOMContentLoaded",(event)=>{
    new QWebChannel(qt.webChannelTransport, function(channel) {
        window.copyBridge = channel.objects.copyBridge;
        window.fileBridge = channel.objects.fileBridge;

        window.hashListBridge = channel.objects.hashListBridge;
        getHashConfig();
        window.paddingListBridge = channel.objects.paddingListBridge;
        getPaddingConfig();
        window.modeListBridge = channel.objects.modeListBridge;
        getModeConfig();
        window.algorithmListBridge = channel.objects.algorithmListBridge;
        getAlgorithmConfig();

        window.exchangeBridge = channel.objects.exchangeBridge;
        window.hashBridge = channel.objects.hashBridge;
        window.encryptionBridge = channel.objects.encryptionBridge;
        window.decryptionBridge = channel.objects.decryptionBridge;

        window.taskBridge = channel.objects.taskBridge;
        
    });
    showing(0,"欢迎使用文件散列加密器!这里是各种消息的显示区域")
})

//文件选择函数
let fileInput = document.getElementsByClassName("file_input_field");
Array.from(fileInput).forEach(node=>{
    //console.log(node.id)
    node.addEventListener("click",(event)=>{
        window.fileBridge.open(
            JSON.stringify(
                {
                    "id": event.target.id,
                }
            )
        );
    })
})
function updateFile(result){
    let target = document.getElementById(result.id);
    while(target.firstChild){
        target.removeChild(target.firstChild);
    }
    let title = document.createElement("p");
    title.innerText = "请点击选择文件或将文件拖拽至窗口";
    target.appendChild(title);
    let file = document.createElement("p");
    file.innerText = "当前文件:"+result.filePath;
    target.appendChild(file);
    target.dataset.path=result.filePath;
    let fileOutputInput = document.getElementById(target.id.split("_")[0]+"_file_output_input");
    if(fileOutputInput === null){
        return;
    }
    if(target.id.split("_")[0] === "encrypt"){
        fileOutputInput.value = target.dataset.path+".crypt";
    }else if(target.id.split("_")[0] === "decrypt"){
        fileOutputInput.value = target.dataset.path+".plain";
    }else{
        fileOutputInput.value = target.dataset.path;
    }
    
}
function dropUpdateFile(filePath){
    let fileInputs = document.querySelectorAll('.input_area:has(.input_type .input_type_file:checked) .file_input_field');
    let choice = document.getElementsByClassName("sidebar_item_active");
    let target = undefined;
    fileInputs.forEach(node=>{
        if(node.id.split("_")[0] === choice[0].id.split("_")[0]){
            target = node;
        }
    })
    if(target === undefined){
        return;
    }
    while(target.firstChild){
        target.removeChild(target.firstChild);
    }
    let title = document.createElement("p");
    title.innerText = "请点击选择文件或将文件拖拽至窗口";
    target.appendChild(title);
    let file = document.createElement("p");
    file.innerText = "当前文件:"+filePath;
    target.appendChild(file);
    target.dataset.path=filePath;
    let fileOutputInput = document.getElementById(target.id.split("_")[0]+"_file_output_input");
    if(target.id.split("_")[0] === "encrypt"){
        fileOutputInput.value = target.dataset.path+".crypt";
    }else if(target.id.split("_")[0] === "decrypt"){
        fileOutputInput.value = target.dataset.path+".plain";
    }else{
        fileOutputInput.value = target.dataset.path;
    }
}
function updateDir(result){
    let target = document.getElementById(result.id);
    target.value = result.dirPath;
}
let fileOutputSaveBtn = document.getElementsByName("file_output_save_btn");
Array.from(fileOutputSaveBtn).forEach(node=>{
    node.addEventListener("click",(event)=>{
        let file_input_field = document.getElementById(event.target.id.split("_")[0]+"_file_input_field");
        window.fileBridge.save(JSON.stringify(
                {
                    "path": file_input_field.dataset.path+"."+event.target.id.split("_")[0],
                    "id": event.target.id.split("_")[0]+"_file_output_input"
                }
            )
        )
    })
})

//文件输出输入框展示
let encryptOutputType = document.getElementsByName("encrypt_output_type");
encryptOutputType.forEach(node=>{
    node.addEventListener("change",(event)=>{
        let encrypt_file_output_field = document.getElementById("encrypt_file_output_field");
        let encrypt_text_output_field = document.getElementById("encrypt_text_output_field");
        if(node.checked && node.value === "3"){
            encrypt_file_output_field.className = "file_output_field_active";
            encrypt_text_output_field.hidden = true;
        }else{
            encrypt_file_output_field.className = "file_output_field";
            encrypt_text_output_field.hidden = false;
        }
    })
})
let decryptOutputType = document.getElementsByName("decrypt_output_type");
decryptOutputType.forEach(node=>{
    node.addEventListener("change",(event)=>{
        let decrypt_file_output_field = document.getElementById("decrypt_file_output_field");
        let decrypt_text_output_field = document.getElementById("decrypt_text_output_field");
        if(node.checked && node.value === "3"){
            decrypt_file_output_field.className = "file_output_field_active";
            decrypt_text_output_field.hidden = true;
        }else{
            decrypt_file_output_field.className = "file_output_field";
            decrypt_text_output_field.hidden = false;
        }
    })
})

//获取散列算法
var hashConfigs = []
function getHashConfig(){
    window.hashListBridge.receive();
}
//only qt接收散列算法
function receiveHashConfig(hashes){
    let hashTypeSelects = document.querySelectorAll("select[data-hash-type=\"true\"]")
    // let hashEffectSelects = document.querySelectorAll("select[data-hash-effect=\"true\"]")
    hashes.forEach(hash=>{
        hashConfigs.push(hash)
    })
    hashTypeSelects.forEach(node=>{
        let nearHashEffectSelect = document.getElementById(node.id.split("hash_type_choice")[0]+"hash_effective_choice");
        while(nearHashEffectSelect.firstChild){
                nearHashEffectSelect.removeChild(nearHashEffectSelect.firstChild);
        }
        let region = hashConfigs[0].region;
        for(let c of region){
            if(c === '|'){
                region = region.replace('|',',');
            }
        }
        region.split(",").forEach(str=>{
            let option = document.createElement("option");
            option.innerText = parseInt(str)*8;
            nearHashEffectSelect.appendChild(option);
        })
        node.addEventListener("change",(event)=>{
            let hashEffectSelect = document.getElementById(event.target.id.split("hash_type_choice")[0]+"hash_effective_choice");
            while(hashEffectSelect.firstChild){
                hashEffectSelect.removeChild(hashEffectSelect.firstChild);
            }
            let opinion = event.target.options[event.target.selectedIndex];
            let region = null;
            hashConfigs.forEach(config=>{
                if(config.name === opinion.innerText){
                    region = config.region;
                }
            })
            for(let c of region){
                if(c === '|'){
                    region = region.replace('|',',');
                }
            }
            region.split(",").forEach(str=>{
                let option = document.createElement("option");
                option.innerText = parseInt(str)*8;
                hashEffectSelect.appendChild(option);
            })
        })
        hashes.forEach(hash=>{
            let option = document.createElement("option");
            option.innerText = hash.name;
            node.appendChild(option);
        })
    })
}

//获得填充方法
var paddingConfigs = []
function getPaddingConfig(){
    window.paddingListBridge.receive();
    //fetch()
}
//only qt接收填充方法
function receivePaddingConfig(paddings){
    let paddingSelects = document.querySelectorAll("select[data-padding=\"true\"]")
    paddings.forEach(padding=>{
        paddingConfigs.push(padding)
    })
    paddingSelects.forEach(node=>{
        paddings.forEach(padding=>{
            let option = document.createElement("option");
            option.value = padding.code;
            option.innerText = padding.name;
            node.appendChild(option);
        })
    })
}

//获得模式
var modeConfigs = []
function getModeConfig(){
    window.modeListBridge.receive();
}
//only qt接收加密模式
function receiveModeConfig(modes){
    let modeSelects = document.querySelectorAll("select[data-mode=\"true\"]")
    modes.forEach(mode=>{
        modeConfigs.push(mode)
    })
    modeSelects.forEach(node=>{
        let isPadding = document.getElementById(node.id.split("_")[0]+"_is_padding");
        isPadding.checked = (modeConfigs[0].forcePadding === true)?true:false;
        isPadding.disabled = (modeConfigs[0].forcePadding === true)?true:false;
        node.addEventListener("change",(event)=>{
            let opinion = event.target.options[event.target.selectedIndex];
            let isPadding = document.getElementById(event.target.id.split("_")[0]+"_is_padding");
            let isShiftFrame = document.getElementById(event.target.id.split("_")[0]+"_setting_shift_frame");
            let isShift = document.getElementById(event.target.id.split("_")[0]+"_shift");
            let blockSize = document.getElementById(event.target.id.split("_")[0]+"_block_size");
            if(opinion.dataset.forcePadding === "true"){
                isPadding.checked = true;
                isPadding.disabled = true;
            }else{
                isPadding.disabled = false;
            }
            if(opinion.dataset.forceShift === "true"){
                isShiftFrame.className = "crypt_setting_shift_frame_active"
                if(opinion.innerText === "CFBB"){
                    isShift.max = blockSize.max;
                }else if(opinion.innerText === "CFBb"){
                    isShift.max = blockSize.max*8;
                }
                isShift.min = 1;
                isShift.value = 1;
            }else{
                isShiftFrame.className = "crypt_setting_shift_frame"
            }
        })
        modes.forEach(mode=>{
            let option = document.createElement("option");
            option.value = mode.code;
            option.innerText = mode.name;
            option.dataset.forcePadding = mode.forcePadding;
            option.dataset.forceShift = mode.forceShift;
            node.appendChild(option);
        })
    })
}

//获取加密算法
var algorithmConfigs = []
function getAlgorithmConfig(){
    window.algorithmListBridge.receive();
}
//only qt接收加密算法
function receiveAlgorithmConfig(algorithms){
    let algorithmSelects = document.querySelectorAll("select[data-algorithm=\"true\"]")
    algorithms.forEach(algorithm=>{
        algorithmConfigs.push(algorithm)
    })
    algorithmSelects.forEach(node=>{
        let blockSize = document.getElementById(node.id.split("_")[0]+"_block_size");
        let keySize = document.getElementById(node.id.split("_")[0]+"_key_size");
        let blockList = breakRegion(algorithmConfigs[0].blockSizeRegion);
        let keyList = breakRegion(algorithmConfigs[0].keySizeRegion);
        blockSize.value = blockList[0];
        blockSize.min = blockList[0];
        blockSize.max = blockList[1];
        blockSize.step = blockList[2];
        keySize.value = keyList[0];
        keySize.min = keyList[0];
        keySize.max = keyList[1];
        keySize.step = keyList[2];
        node.addEventListener("change",(event)=>{
            let blockSize = document.getElementById(event.target.id.split("_")[0]+"_block_size");
            let keySize = document.getElementById(event.target.id.split("_")[0]+"_key_size");
            let opinion = event.target.options[event.target.selectedIndex];
            let blockList = breakRegion(opinion.dataset.blockSizeRegion);
            let keyList = breakRegion(opinion.dataset.keySizeRegion);
            blockSize.value = blockList[0];
            blockSize.min = blockList[0];
            blockSize.max = blockList[1];
            blockSize.step = blockList[2];
            keySize.value = keyList[0];
            keySize.min = keyList[0];
            keySize.max = keyList[1];
            keySize.step = keyList[2];                
        })
        algorithms.forEach(algorithm=>{
            let option = document.createElement("option");
            option.value = algorithm.name;
            option.innerText = algorithm.name;
            option.dataset.blockSizeRegion = algorithm.blockSizeRegion;
            option.dataset.keySizeRegion = algorithm.keySizeRegion;
            node.appendChild(option);
        })
    })
    algorithmConfigs.forEach(algorithm=>{

    })
}

//获取常规输入输出
function getNormalInputOutput(id){
    let args = {}
    let textInput = document.getElementById(id+"_text_input");
    let input = textInput.value;
    if(input === ""){
        showing(1,"请输入内容")
        return;
    }
    let inputType = document.querySelector("input[type=\"radio\"][name=\""+id+"_input_type\"]:checked");
    if(inputType.value==="1"){
        let replace0 = document.getElementById(id+"_input_base64_replace+").value;//+
        let replace1 = document.getElementById(id+"_input_base64_replace/").value;// /
        let replace2 = document.getElementById(id+"_input_base64_replace=").value;//=
        if(replace0 === replace1 || replace0 === replace2 || replace1 === replace2){
            showing(1,"替换字符不能相同")
        }
        while(input.indexOf(replace0) !== -1 && replace0 !== "+"){
            input = input.replace(replace0,"+");
        }
        while(input.indexOf(replace1) !== -1 && replace1 !== "/"){
            input = input.replace(replace1,"/");
        }
        while(input.indexOf(replace2) !== -1 && replace2 !== "="){
            input = input.replace(replace2,"=");
        }
        const regex = /[^A-Za-z0-9\+\/\=]/g;
        if(regex.test(input)){
            showing(1,"输入内容含有非法字符,base64仅可以为0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"+replace0+replace1+replace2)
            return;
        }
    }else if(inputType.value==="2"){
        const regex = /[^0-9a-fA-F]/g;
        if(regex.test(input)){
            showing(1,"输入内容含有非法字符,hex仅可以为0123456789abcdefABCDEF")
            return;
        }
    }
    args.input = input;
    args.inputType = parseInt(inputType.value);
    let outputType = document.querySelector("input[type=\"radio\"][name=\""+id+"_output_type\"]:checked");
    args.outputType = parseInt(outputType.value);
    if(outputType.value==="1"){
        args.replace0 = document.getElementById(id+"_output_base64_replace+").value;//+
        args.replace1 = document.getElementById(id+"_output_base64_replace/").value;// /
        args.replace2 = document.getElementById(id+"_output_base64_replace=").value;//=
        if(args.replace0 === args.replace1 || args.replace0 === args.replace2 || args.replace1 === args.replace2){
            showing(1,"替换字符不能相同")
            return;
        }
    }else if(outputType.value==="2"){
        args.upper = document.getElementById(id+"_output_hex_case_upper").checked;
    }
    return args;
}
function getInput(id){
    let args = {}
    let idTextInput = document.getElementById(id+"_text_input");
    let input = idTextInput.value;
    let idInputType = document.querySelector("input[type=\"radio\"][name=\""+id+"_input_type\"]:checked");
    if(idInputType.value==="0") {
        if(input === ""){
            showing(1,"请输入内容")
            return;
        }
        args.input = input;
    }else if(idInputType.value==="1"){
        if(input === ""){
            showing(1,"请输入内容")
            return;
        }
        let replace0 = document.getElementById(id+"_input_base64_replace+").value;//+
        let replace1 = document.getElementById(id+"_input_base64_replace/").value;// /
        let replace2 = document.getElementById(id+"_input_base64_replace=").value;//=
        if(replace0 === replace1 || replace0 === replace2 || replace1 === replace2){
            showing(1,"替换字符不能相同")
        }
        while(input.indexOf(replace0) !== -1 && replace0 !== "+"){
            input = input.replace(replace0,"+");
        }
        while(input.indexOf(replace1) !== -1 && replace1 !== "/"){
            input = input.replace(replace1,"/");
        }
        while(input.indexOf(replace2) !== -1 && replace2 !== "="){
            input = input.replace(replace2,"=");
        }
        const regex = /[^A-Za-z0-9\+\/\=]/g;
        if(regex.test(input)){
            showing(1,"输入内容含有非法字符,base64仅可以为0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"+replace0+replace1+replace2)
            return;
        }
        args.input = input;
    }else if(idInputType.value==="2"){
        if(input === ""){
            showing(1,"请输入内容")
            return;
        }
        const regex = /[^0-9a-fA-F]/g;
        if(regex.test(input)){
            showing(1,"输入内容含有非法字符,hex仅可以为0123456789abcdefABCDEF")
            return;
        }
        args.input = input;
    }else if(idInputType.value==="3"){
        let idFileInputField = document.getElementById(id+"_file_input_field");
        if(idFileInputField.dataset.path === ""){
            showing(1,"请选择文件")
            return;
        }
        args.input = idFileInputField.dataset.path;
    }
    args.inputType = parseInt(idInputType.value);
    let idOutputType = document.querySelector("input[type=\"radio\"][name=\""+id+"_output_type\"]:checked");
    args.outputType = parseInt(idOutputType.value);
    if(idOutputType.value==="1"){
        args.replace0 = document.getElementById(id+"_output_base64_replace+").value;//+
        args.replace1 = document.getElementById(id+"_output_base64_replace/").value;// /
        args.replace2 = document.getElementById(id+"_output_base64_replace=").value;//=
        if(args.replace0 === args.replace1 || args.replace0 === args.replace2 || args.replace1 === args.replace2){
            showing(1,"替换字符不能相同")
            return;
        }
    }else if(idOutputType.value==="2"){
        args.upper = document.getElementById(id+"_output_hex_case_upper").checked;
    }else if(idOutputType.value==="3"){
        args.output = document.getElementById(id+"_file_output_input").value;
    }
    return args;
}
function getInputNoOutput(id){
    let args = {}
    let idTextInput = document.getElementById(id+"_text_input");
    let input = idTextInput.value;
    let idInputType = document.querySelector("input[type=\"radio\"][name=\""+id+"_input_type\"]:checked");
    if(idInputType.value==="0") {
        args.input = input;
    }else if(idInputType.value==="1"){
        let replace0 = document.getElementById(id+"_input_base64_replace+").value;//+
        let replace1 = document.getElementById(id+"_input_base64_replace/").value;// /
        let replace2 = document.getElementById(id+"_input_base64_replace=").value;//=
        if(replace0 === replace1 || replace0 === replace2 || replace1 === replace2){
            showing(1,"替换字符不能相同")
        }
        while(input.indexOf(replace0) !== -1 && replace0 !== "+"){
            input = input.replace(replace0,"+");
        }
        while(input.indexOf(replace1) !== -1 && replace1 !== "/"){
            input = input.replace(replace1,"/");
        }
        while(input.indexOf(replace2) !== -1 && replace2 !== "="){
            input = input.replace(replace2,"=");
        }
        const regex = /[^A-Za-z0-9\+\/\=]/g;
        if(regex.test(input)){
            showing(1,"输入内容含有非法字符,base64仅可以为0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"+replace0+replace1+replace2)
            return;
        }
        args.input = input;
    }else if(idInputType.value==="2"){
        const regex = /[^0-9a-fA-F]/g;
        if(regex.test(input)){
            showing(1,"输入内容含有非法字符,hex仅可以为0123456789abcdefABCDEF")
            return;
        }
        args.input = input;
    }else if(idInputType.value==="3"){
        let idFileInputField = document.getElementById(id+"_file_input_field");
        if(idFileInputField.dataset.path === ""){
            showing(1,"请选择文件")
            return;
        }
        args.input = idFileInputField.dataset.path;
    }
    args.inputType = parseInt(idInputType.value);
    return args;
}
function getInputAllowEmpty(id){
    let args = {}
    let idTextInput = document.getElementById(id+"_text_input");
    let input = idTextInput.value;
    let idInputType = document.querySelector("input[type=\"radio\"][name=\""+id+"_input_type\"]:checked");
    if(idInputType.value==="0") {
        args.input = input;
    }else if(idInputType.value==="1"){
        let replace0 = document.getElementById(id+"_input_base64_replace+").value;//+
        let replace1 = document.getElementById(id+"_input_base64_replace/").value;// /
        let replace2 = document.getElementById(id+"_input_base64_replace=").value;//=
        if(replace0 === replace1 || replace0 === replace2 || replace1 === replace2){
            showing(1,"替换字符不能相同")
        }
        while(input.indexOf(replace0) !== -1 && replace0 !== "+"){
            input = input.replace(replace0,"+");
        }
        while(input.indexOf(replace1) !== -1 && replace1 !== "/"){
            input = input.replace(replace1,"/");
        }
        while(input.indexOf(replace2) !== -1 && replace2 !== "="){
            input = input.replace(replace2,"=");
        }
        const regex = /[^A-Za-z0-9\+\/\=]/g;
        if(regex.test(input)){
            showing(1,"输入内容含有非法字符,base64仅可以为0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"+replace0+replace1+replace2)
            return;
        }
        args.input = input;
    }else if(idInputType.value==="2"){
        const regex = /[^0-9a-fA-F]/g;
        if(regex.test(input)){
            showing(1,"输入内容含有非法字符,hex仅可以为0123456789abcdefABCDEF")
            return;
        }
        args.input = input;
    }else if(idInputType.value==="3"){
        let idFileInputField = document.getElementById(id+"_file_input_field");
        if(idFileInputField.dataset.path === ""){
            showing(1,"请选择文件")
            return;
        }
        args.input = idFileInputField.dataset.path;
    }
    args.inputType = parseInt(idInputType.value);
    let idOutputType = document.querySelector("input[type=\"radio\"][name=\""+id+"_output_type\"]:checked");
    args.outputType = parseInt(idOutputType.value);
    if(idOutputType.value==="1"){
        args.replace0 = document.getElementById(id+"_output_base64_replace+").value;//+
        args.replace1 = document.getElementById(id+"_output_base64_replace/").value;// /
        args.replace2 = document.getElementById(id+"_output_base64_replace=").value;//=
        if(args.replace0 === args.replace1 || args.replace0 === args.replace2 || args.replace1 === args.replace2){
            showing(1,"替换字符不能相同")
            return;
        }
    }else if(idOutputType.value==="2"){
        args.upper = document.getElementById(id+"_output_hex_case_upper").checked;
    }else if(idOutputType.value==="3"){
        args.outputPath = document.getElementById(id+"_file_output_input").value;
    }
    return args;
}

//转换相关操作
let exchangeButton = document.getElementById("exchange_button");
exchangeButton.addEventListener("click",()=>{
    let args = getInput("exchange");
    //console.log(args)
    if(args===undefined){
        return;
    }
    window.exchangeBridge.receive(JSON.stringify(args))
})
function qtExchangeBack(result){
    if(result.code !== 0){
        showing(1,result.msg)
        document.getElementById("exchange_resolve_time").textContent = "出错";
        return;
    }
    showing(0,"转换成功")
    document.getElementById("exchange_text_output").value = result.res;
    document.getElementById("exchange_resolve_time").textContent = "耗时:"+fmtTime(result.time);
}
let exchangeOutputTextCopy = document.getElementById("exchange_output_text_copy");
exchangeOutputTextCopy.addEventListener("click",()=>{
    let exchangeOutputText = document.getElementById("exchange_text_output");
    if(exchangeOutputText.value === ""){
        return;
    }
    copyToClipboard(exchangeOutputText.value);

})

//散列相关操作
let hashButton = document.getElementById("hash_button");
hashButton.addEventListener("click",()=>{
    let args = getInputAllowEmpty("hash");
    if(args===undefined){
        return;
    }
    let hash_type_choice = document.getElementById("hash_type_choice");
    let hash_type = hash_type_choice.value;
    let hash_effective_choice = document.getElementById("hash_effective_choice");
    let hash_effective = hash_effective_choice.value;
    args.type = hash_type;
    args.effective = parseInt(parseInt(hash_effective)/8);
    //console.log(args)
    window.hashBridge.work(JSON.stringify(args))
})
function updateHashResult(result){
    let hash_text_output = document.getElementById("hash_text_output");
    let hash_resolve_time = document.getElementById("hash_resolve_time");
    showing(result.code,result.msg)
    if(result.code !== 0){
        hash_resolve_time.textContent = "出错";
        return;
    }
    if(result.file === true){
        return;
    }
    hash_text_output.value = result.res;
    hash_resolve_time.textContent = "耗时:"+fmtTime(result.time);
}
let hashSpeedTest = document.getElementById("hash_speed_test");
hashSpeedTest.addEventListener("click",()=>{
    let hash_type_choice = document.getElementById("hash_type_choice");
    let hash_type = hash_type_choice.value;
    let hash_effective_choice = document.getElementById("hash_effective_choice");
    let hash_effective = hash_effective_choice.value;
    let param = {
        "type":hash_type,
        "effective":parseInt(parseInt(hash_effective)/8),
    }
    window.hashBridge.test(JSON.stringify(param));
})
function updateHashSpeed(result){
    let hashSpeedResult = document.getElementById("hash_speed_result");
    hashSpeedResult.textContent = "耗时:"+fmtTime(result.time);
}
let hashOutputTextCopy = document.getElementById("hash_output_text_copy");
hashOutputTextCopy.addEventListener("click",()=>{
    let hashOutputText = document.getElementById("hash_text_output");
    if(hashOutputText.value === ""){
        return;
    }
    copyToClipboard(hashOutputText.value);
})

function sizeBack(result){
    if(result.code !== 0){
        showing(1,result.msg)
        return;
    }
    let target = document.getElementById(result.id)
    if(result.size === "overflow"){
        target.textContent = "当前:超出最大值"
        target.dataset.size = 0;
    }else{
        target.textContent = "当前:"+result.size+"字节(B)"
        target.dataset.size = parseInt(result.size);
    }
}

//加密相关操作
let encryptFileOutputSaveBtn = document.getElementById("encrypt_file_output_save_btn");
encryptFileOutputSaveBtn.addEventListener("click",()=>{
    let encrypt_file_input_field = document.getElementById("encrypt_file_input_field");
    window.fileBridge.save(JSON.stringify(
            {
                "path": (encrypt_file_input_field.dataset.path===undefined)?(""):(encrypt_file_input_field.dataset.path+".encrypt"),
                "id": "encrypt_file_output_input"
            }
        )
    )
})
let encryptInputType = document.getElementsByName("encrypt_input_type");
encryptInputType.forEach((inputChoice)=>{
    inputChoice.addEventListener("change",(event)=>{
        let target = event.target;
        let encryptOutputType = document.getElementsByName("encrypt_output_type");
        let encrypt_file_output_field = document.getElementById("encrypt_file_output_field");
        let encrypt_text_output_field = document.getElementById("encrypt_text_output_field");
        if(target.checked && target.value === "3"){
            encryptOutputType.forEach((outputChoice)=>{
                if(outputChoice.value === "3"){
                    outputChoice.checked = true;
                    encrypt_file_output_field.className = "file_output_field_active";
                    encrypt_text_output_field.hidden = true;
                }else{
                    outputChoice.disabled = true;
                }
            })
        }else{
            encryptOutputType.forEach((outputChoice)=>{
                if(outputChoice.value === "3"){
                    outputChoice.checked = false;
                    encrypt_file_output_field.className = "file_output_field";
                    encrypt_text_output_field.hidden = false;
                }else if(outputChoice.value === "2"){
                    outputChoice.checked = true;
                    outputChoice.disabled = false;
                }else{
                    outputChoice.disabled = false;
                }
            })
        }
    })
})
let encrypt_key_input_type = document.getElementsByName("encrypt_key_input_type");
encrypt_key_input_type.forEach((inputChoice)=>{
    inputChoice.addEventListener("change",(event)=>{
        let args = getInputNoOutput("encrypt_key");
        if(args === undefined){
            let encrypt_key_text_input_size = document.getElementById("encrypt_key_text_input_size");
            encrypt_key_text_input_size.textContent = "输入格式不正确";
            encrypt_key_text_input_size.dataset.size=0;
            return;
        }
        args.id = "encrypt_key_text_input_size";
        //console.log(args)
        window.exchangeBridge.get_data_size(JSON.stringify(args))
    })
})
let encrypt_key_text_input = document.getElementById("encrypt_key_text_input");
encrypt_key_text_input.addEventListener("input",()=>{
    let args = getInputNoOutput("encrypt_key");
    if(args === undefined){
        let encrypt_key_text_input_size = document.getElementById("encrypt_key_text_input_size");
        encrypt_key_text_input_size.textContent = "输入格式不正确";
        encrypt_key_text_input_size.dataset.size=0;
        return;
    }
    args.id = "encrypt_key_text_input_size";
    //console.log(args)
    window.exchangeBridge.get_data_size(JSON.stringify(args))
})
let encrypt_mode = document.getElementById("encrypt_mode");
encrypt_mode.addEventListener("change",(event)=>{
    let mode = null;
    modeConfigs.forEach((config)=>{
        console.log(config)
        if(config.code === parseInt(event.target.value)){
            mode = config;
        }
    })
    let encrypt_is_iv = document.getElementById("encrypt_is_iv");
    let encrypt_iv_field = document.getElementById("encrypt_iv_field");
    if(mode.forceIv){
        encrypt_is_iv.checked = true;
        encrypt_iv_field.style.display = "flex"
        encrypt_is_iv.disabled = true;
    }else{
        encrypt_is_iv.disabled = false;
    }
})
let encrypt_is_iv = document.getElementById("encrypt_is_iv");
encrypt_is_iv.addEventListener("change",(event)=>{
    let encrypt_iv_field = document.getElementById("encrypt_iv_field");
    if(event.target.checked){
        encrypt_iv_field.style.display = "flex"
    }else{
        encrypt_iv_field.style.display = "none"
    }
})
let encrypt_iv_input_type = document.getElementsByName("encrypt_iv_input_type");
encrypt_iv_input_type.forEach((inputChoice)=>{
    inputChoice.addEventListener("change",(event)=>{
        let args = getInputNoOutput("encrypt_iv");
        if(args === undefined){
            let encrypt_iv_text_input_size = document.getElementById("encrypt_iv_text_input_size");
            encrypt_iv_text_input_size.textContent = "输入格式不正确";
            encrypt_key_text_input_size.dataset.size=0;
            return;
        }
        args.id = "encrypt_iv_text_input_size";
        //console.log(args)
        window.exchangeBridge.get_data_size(JSON.stringify(args))
    })
})
let encrypt_iv_text_input = document.getElementById("encrypt_iv_text_input");
encrypt_iv_text_input.addEventListener("input",()=>{
    let args = getInputNoOutput("encrypt_iv");
    if(args === undefined){
        let encrypt_key_text_input_size = document.getElementById("encrypt_iv_text_input_size");
        encrypt_key_text_input_size.textContent = "输入格式不正确";
        encrypt_key_text_input_size.dataset.size=0;
        return;
    }
    args.id = "encrypt_iv_text_input_size";
    //console.log(args)
    window.exchangeBridge.get_data_size(JSON.stringify(args))
})
let encrypt_speed_test = document.getElementById("encrypt_speed_test");
encrypt_speed_test.addEventListener("click",()=>{
    let encrypt_method = document.getElementById("encrypt_method");
    let encrypt_block_size = document.getElementById("encrypt_block_size");
    let encrypt_key_size = document.getElementById("encrypt_key_size");
    let encrypt_type = encrypt_method.value;
    let encrypt_block = encrypt_block_size.value;
    let encrypt_key = encrypt_key_size.value;
    let args = {
        "type":encrypt_type,
        "blockSize":parseInt(encrypt_block),
        "keySize":parseInt(encrypt_key)
    }
    window.encryptionBridge.test(JSON.stringify(args))
})
function updateEncryptionSpeed(result){
    let encrypt_speed_result = document.getElementById("encrypt_speed_result");
    if(result.code !== 0){
        showing(1,result.msg)
        encrypt_speed_result.textContent = "出错";
        return;
    }
    encrypt_speed_result.textContent = "耗时:"+fmtTime(result.time);
}
let encrypt_button = document.getElementById("encrypt_button");
encrypt_button.addEventListener("click",()=>{
    let params = {};
    let args = getInput("encrypt");
    if(args === undefined){
        return;
    }
    params.input= args;
    let config = {};
    let encrypt_method = document.getElementById("encrypt_method");
    let encrypt_block_size = document.getElementById("encrypt_block_size");
    let encrypt_key_size = document.getElementById("encrypt_key_size");
    let encrypt_type = encrypt_method.value;
    let encrypt_block = encrypt_block_size.value;
    let encrypt_key = encrypt_key_size.value;
    config.type = encrypt_type;
    config.blockSize = parseInt(encrypt_block);
    config.keySize = parseInt(encrypt_key);

    let encrypt_mode = document.getElementById("encrypt_mode");
    let temp_mode = encrypt_mode.value;
    modeConfigs.forEach((mode)=>{
        if(parseInt(mode.code) === parseInt(temp_mode)){
            config.mode = mode.name;
        }
    })

    let encrypt_is_padding = document.getElementById("encrypt_is_padding");
    config.isPadding = encrypt_is_padding.checked;

    let encrypt_padding = document.getElementById("encrypt_padding");
    let temp_padding = encrypt_padding.value;
    paddingConfigs.forEach((padding)=>{
        if(parseInt(padding.code) === parseInt(temp_padding)){
            config.padding = padding.name;
        }
    })

    let encrypt_shift = document.getElementById("encrypt_shift");
    let temp_shift = parseInt(encrypt_shift.value);
    if(temp_shift > config.blockSize && temp_mode === "CFBB"){
        showing(1,"CFBB模式位移量不能大于块大小");
        return;
    }else if(temp_shift > config.blockSize*8 && temp_mode === "CFBb"){
        showing(1,"CFBb模式位移量不能大于块大小*8");
        return;
    }
    config.shift = temp_shift;
    params.config = config;

    let encrypt_key_text_input_size = document.getElementById("encrypt_key_text_input_size");
    if(encrypt_key_text_input_size.dataset.size < config.keySize){
        showing(1,"密钥长度不足,应为"+config.keySize+"位(B),当前为"+encrypt_key_text_input_size.dataset.size+"位(B)");
        return;
    }
    let key = getInputNoOutput("encrypt_key");
    if(key===undefined){
        return;
    }
    
    let encrypt_auto_iv = document.getElementById("encrypt_auto_iv");
    if(encrypt_auto_iv.checked){
        let iv = {}
        iv.auto = true;
        params.iv = iv;
    }
    else{
        let encrypt_iv_text_input_size = document.getElementById("encrypt_iv_text_input_size");
        if(encrypt_iv_text_input_size.dataset.size < config.blockSize){
            showing(1,"iv长度不足,应为"+config.blockSize+"位(B),当前为"+encrypt_iv_text_input_size.dataset.size+"位(B)");
            return;
        }
        let iv = getInputNoOutput("encrypt_iv");
        if(iv===undefined){
            return;
        }
        params.iv = iv;
    }
    params.key = key;
    head={};
    let encrypt_with_config = document.getElementById("encrypt_with_config");
    let encrypt_with_iv = document.getElementById("encrypt_with_iv");
    let encrypt_with_check = document.getElementById("encrypt_with_check");
    head.withConfig = encrypt_with_config.checked;
    head.withIV = encrypt_with_iv.checked;
    head.withCheck = encrypt_with_check.checked;
    params.head = head;
    //console.log(params)
    window.encryptionBridge.work(JSON.stringify(params))
})
function updateEncryptionResult(result){
    showing(result.code,result.msg)
    if(result.file === true){
        return;
    }
    let encrypt_resolve_time = document.getElementById("encrypt_resolve_time");
    let encrypt_text_output = document.getElementById("encrypt_text_output");
    encrypt_text_output.value = result.res;
    if(result.code !== 0){
        encrypt_resolve_time.textContent = "出错";
    }else{
        encrypt_resolve_time.textContent = "耗时:"+fmtTime(result.time);
    }
    if(result.iv !== undefined){
        let encrypt_iv_text_input = document.getElementById("encrypt_iv_text_input");
        encrypt_iv_text_input.value = result.iv;
        let encrypt_iv_input_type_hex = document.getElementById("encrypt_iv_input_type_hex");
        encrypt_iv_input_type_hex.checked = true;
        encrypt_iv_text_input.dispatchEvent(new Event("input"));
    }

}
let encrypt_output_text_copy = document.getElementById("encrypt_output_text_copy");
encrypt_output_text_copy.addEventListener("click",()=>{
    let encrypt_text_output = document.getElementById("encrypt_text_output");
    if(encrypt_text_output.value === ""){
        return;
    }
    copyToClipboard(encrypt_text_output.value);
})

//解密相关操作
let decrypt_input_type = document.getElementsByName("decrypt_input_type")
decrypt_input_type.forEach((item)=>{
    item.addEventListener("click",()=>{
        let decrypt_output_type = document.getElementsByName("decrypt_output_type")
        let decrypt_output_type_file = document.getElementById("decrypt_output_type_file");
        let decrypt_output_type_utf8 = document.getElementById("decrypt_output_type_utf8");
        let decrypt_file_output_field = document.getElementById("decrypt_file_output_field");
        let decrypt_text_output_field = document.getElementById("decrypt_text_output_field");
        if(item.value === "3"){
            decrypt_output_type_file.checked = true;
            decrypt_file_output_field.className = "file_output_field_active";
            decrypt_text_output_field.hidden = true;
            decrypt_output_type.forEach((item)=>{
                item.disabled = true;
            })
        }else{
            decrypt_output_type_utf8.checked = true;
            decrypt_file_output_field.className = "file_output_field";
            decrypt_text_output_field.hidden = false;
            decrypt_output_type.forEach((item)=>{
                item.disabled = false;
            })
        }
    })
})
let decrypt_speed_test = document.getElementById("decrypt_speed_test");
decrypt_speed_test.addEventListener("click",()=>{
    let decrypt_method = document.getElementById("decrypt_method");
    let decrypt_block_size = document.getElementById("decrypt_block_size");
    let decrypt_key_size = document.getElementById("decrypt_key_size");
    let decrypt_type = decrypt_method.value;
    let decrypt_block = decrypt_block_size.value;
    let decrypt_key = decrypt_key_size.value;
    let args = {
        "type":decrypt_type,
        "blockSize":parseInt(decrypt_block),
        "keySize":parseInt(decrypt_key)
    }
    window.decryptionBridge.test(JSON.stringify(args))
})
function updateDecryptionSpeed(result){
    let decrypt_speed_result = document.getElementById("decrypt_speed_result");
    if(result.code !== 0){
        showing(1,result.msg)
        decrypt_speed_result.textContent = "出错";
        return;
    }
    decrypt_speed_result.textContent = "耗时:"+fmtTime(result.time);
}
let decrypt_key_input_type = document.getElementsByName("decrypt_key_input_type")
decrypt_key_input_type.forEach((outputChoice)=>{
    outputChoice.addEventListener("change",()=>{
        let args = getInputNoOutput("decrypt_key");
        if(args === undefined){
            let decrypt_key_text_input_size = document.getElementById("decrypt_key_text_input_size");
            decrypt_key_text_input_size.textContent = "输入格式不正确";
            decrypt_key_text_input_size.dataset.size=0;
            return;
        }
        args.id = "decrypt_key_text_input_size";
        //console.log(args)
        window.exchangeBridge.get_data_size(JSON.stringify(args))
    })
})
let decrypt_key_text_input = document.getElementById("decrypt_key_text_input");
decrypt_key_text_input.addEventListener("input",()=>{
    let args = getInputNoOutput("decrypt_key");
    if(args === undefined){
        let decrypt_key_text_input_size = document.getElementById("decrypt_key_text_input_size");
        decrypt_key_text_input_size.textContent = "输入格式不正确";
        decrypt_key_text_input_size.dataset.size=0;
        return;
    }
    args.id = "decrypt_key_text_input_size";
    //console.log(args)
    window.exchangeBridge.get_data_size(JSON.stringify(args))
})
let decrypt_iv_input_type = document.getElementsByName("decrypt_iv_input_type")
decrypt_iv_input_type.forEach((outputChoice)=>{
    outputChoice.addEventListener("change",()=>{
        let args = getInputNoOutput("decrypt_iv");
        if(args === undefined){
            let decrypt_iv_text_input_size = document.getElementById("decrypt_iv_text_input_size");
            decrypt_iv_text_input_size.textContent = "输入格式不正确";
            decrypt_iv_text_input_size.dataset.size=0;
            return;
        }
        args.id = "decrypt_iv_text_input_size";
        //console.log(args)
        window.exchangeBridge.get_data_size(JSON.stringify(args))
    })
})
let decrypt_iv_text_input = document.getElementById("decrypt_iv_text_input");
decrypt_iv_text_input.addEventListener("input",()=>{
    let args = getInputNoOutput("decrypt_iv");
    if(args === undefined){
        let decrypt_iv_text_input_size = document.getElementById("decrypt_iv_text_input_size");
        decrypt_iv_text_input_size.textContent = "输入格式不正确";
        decrypt_iv_text_input_size.dataset.size=0;
        return;
    }
    args.id = "decrypt_iv_text_input_size";
    //console.log(args)
    window.exchangeBridge.get_data_size(JSON.stringify(args))
})
let decrypt_button = document.getElementById("decrypt_button");
decrypt_button.addEventListener("click",()=>{
    let params = {};
    let args = getInput("decrypt");
    if(args === undefined){
        return;
    }
    params.input= args;
    let config = {};
    let decrypt_method = document.getElementById("decrypt_method");
    let decrypt_block_size = document.getElementById("decrypt_block_size");
    let decrypt_key_size = document.getElementById("decrypt_key_size");
    let decrypt_type = decrypt_method.value;
    let decrypt_block = decrypt_block_size.value;
    let decrypt_key = decrypt_key_size.value;
    config.type = decrypt_type;
    config.blockSize = parseInt(decrypt_block);
    config.keySize = parseInt(decrypt_key);

    let decrypt_mode = document.getElementById("decrypt_mode");
    let temp_mode = decrypt_mode.value;
    modeConfigs.forEach((mode)=>{
        if(parseInt(mode.code) === parseInt(temp_mode)){
            config.mode = mode.name;
        }
    })

    let decrypt_is_padding = document.getElementById("decrypt_is_padding");
    config.isPadding = decrypt_is_padding.checked;

    let decrypt_padding = document.getElementById("decrypt_padding");
    let temp_padding = decrypt_padding.value;
    paddingConfigs.forEach((padding)=>{
        if(parseInt(padding.code) === parseInt(temp_padding)){
            config.padding = padding.name;
        }
    })

    let decrypt_shift = document.getElementById("decrypt_shift");
    let temp_shift = parseInt(decrypt_shift.value);
    if(temp_shift > config.blockSize && temp_mode === "CFBB"){
        showing(1,"CFBB模式位移量不能大于块大小");
        return;
    }else if(temp_shift > config.blockSize*8 && temp_mode === "CFBb"){
        showing(1,"CFBb模式位移量不能大于块大小*8");
        return;
    }
    config.shift = temp_shift;
    params.config = config;

    let decrypt_key_text_input_size = document.getElementById("decrypt_key_text_input_size");
    if(decrypt_key_text_input_size.dataset.size < config.keySize){
        showing(1,"密钥长度不足,应为"+config.keySize+"位(B),当前为"+decrypt_key_text_input_size.dataset.size+"位(B)");
        return;
    }
    let key = getInputNoOutput("decrypt_key");
    if(key===undefined){
        return;
    }
    
    let decrypt_iv_text_input_size = document.getElementById("decrypt_iv_text_input_size");
    if(decrypt_iv_text_input_size.dataset.size < config.blockSize){
        showing(1,"iv长度不足,应为"+config.blockSize+"位(B),当前为"+decrypt_iv_text_input_size.dataset.size+"位(B)");
        return;
    }
    let iv = getInputNoOutput("decrypt_iv");
    if(iv===undefined){
        return;
    }
    params.iv = iv;
    params.key = key;

    head={};
    let decrypt_with_config = document.getElementById("decrypt_with_config");
    let decrypt_with_iv = document.getElementById("decrypt_with_iv");
    let decrypt_with_check = document.getElementById("decrypt_with_check");
    head.withConfig = decrypt_with_config.checked;
    head.withIV = decrypt_with_iv.checked;
    head.withCheck = decrypt_with_check.checked;
    params.head = head;
    //console.log(params)
    window.decryptionBridge.work(JSON.stringify(params))
})
function updateDecryptionResult(result){
    showing(result.code,result.msg)
    if(result.file === true){
        return;
    }
    let decrypt_resolve_time = document.getElementById("decrypt_resolve_time");
    let decrypt_text_output = document.getElementById("decrypt_text_output");
    decrypt_text_output.value = result.res;
    if(result.code !== 0){
        decrypt_resolve_time.textContent = "出错";
    }else{
        decrypt_resolve_time.textContent = "耗时:"+fmtTime(result.time);
    }
    if(result.iv !== undefined){
        let decrypt_iv_text_input = document.getElementById("decrypt_iv_text_input");
        decrypt_iv_text_input.value = result.iv;
        let decrypt_iv_input_type_hex = document.getElementById("decrypt_iv_input_type_hex");
        decrypt_iv_input_type_hex.checked = true;
        decrypt_iv_text_input.dispatchEvent(new Event("input"));
    }

}
let decrypt_output_text_copy = document.getElementById("decrypt_output_text_copy");
decrypt_output_text_copy.addEventListener("click",()=>{
    let decrypt_text_output = document.getElementById("decrypt_text_output");
    if(decrypt_text_output.value === ""){
        return;
    }
    copyToClipboard(decrypt_text_output.value);
})

var running_id= new Set();
var waitting_id = []
//任务相关
const intervalId = setInterval(() => {
  try{
    window.taskBridge.get_all_running();
    window.taskBridge.get_all_waitting();
  }catch(e){
    console.log(e);
  }
}, 10);
setInterval(() => {
  try{
    running_task_list.childNodes.forEach((area)=>{
        if(area.className === "single_task_area"){
            let id = area.dataset.id;
            let change = false;
            area.childNodes.forEach((child)=>{
                if(child.className === "single_task_status" && child.textContent === "完成"){
                    change = true;
                }
                if(child.className === "single_task_operation" && change){
                    while(child.firstChild){
                        child.firstChild.remove();
                    }
                    let single_task_delete_btn = document.createElement("div");
                    single_task_delete_btn.className = "single_task_delete_btn";
                    single_task_delete_btn.textContent = "删除";
                    single_task_delete_btn.addEventListener("click",()=>{
                        let single_task_area = document.querySelector(`.single_task_area[data-id='${id}']`);
                        single_task_area.dataset.info = "";
                        single_task_area.remove();
                        let task_info = document.getElementById("task_info");
                        while(task_info.firstChild){
                            task_info.removeChild(task_info.firstChild);
                        }
                    })
                    child.appendChild(single_task_delete_btn);
                }
            })
        }
    })
  }catch(e){
    console.log(e);
  }
}, 5000);

function showInfo(task){
    if(task === ""){return;}
    task = JSON.parse(task);
    let task_info = document.getElementById("task_info");
    while(task_info.firstChild){
        task_info.removeChild(task_info.firstChild);
    }
    let title = document.createElement("div");
    title.className = "task_info_title";
    let input = document.createElement("div");
    input.className = "task_info_item";
    input.textContent = "输入文件\n"+task.input;
    let config = document.createElement("div");
    config.className = "task_info_item";
    if(task.type === "hash"){
        title.textContent = "文件散列计算";
        config.textContent = "任务配置\n"+task.hash;
        task_info.appendChild(title);
        task_info.appendChild(input);
        task_info.appendChild(config);
        let resultType = document.createElement("div");
        resultType.className = "task_info_item";
        resultType.textContent = "输出类型\n" + task.output_type;
        task_info.appendChild(resultType);
        if(task.status === 2){
            let result = document.createElement("div");
            result.className = "task_info_item";
            result.textContent = "计算结果\n"+task.result;
            task_info.appendChild(result);
            let copy_btn = document.createElement("button");
            copy_btn.className = "task_info_item";
            copy_btn.textContent = "复制";
            copy_btn.addEventListener("click",()=>{
                copyToClipboard(task.result);
            })
            task_info.appendChild(copy_btn);
        }
    }else{
        if(task.type === "encrypt"){
            title.textContent = "文件对称加密";
        }else if(task.type === "decrypt"){
            title.textContent = "文件对称解密";
        }
        config.textContent = "任务配置\n"+task.config;
        task_info.appendChild(title);
        task_info.appendChild(input);
        task_info.appendChild(config);
        let output = document.createElement("div");
        output.className = "task_info_item";
        output.textContent = "输出文件\n"+task.output;
        task_info.appendChild(output);
        if(task.msg !== undefined){
            let msg = document.createElement("div");
            msg.className = "task_info_item";
            msg.textContent = "过程消息\n"+task.msg;
            task_info.appendChild(msg);
        }
    }
}

function addWaittingTask(task){
    let single_task_area = document.createElement("div");
    single_task_area.dataset.info = JSON.stringify(task);
    single_task_area.className = "single_task_area";
    single_task_area.dataset.id = task.id;
    let single_task_title = document.createElement("div");
    single_task_title.className = "single_task_title";
    let single_task_info = document.createElement("div");
    single_task_info.className = "single_task_info";
    if(task.type === "hash"){
        single_task_title.textContent = "文件散列计算";
        single_task_info.textContent = task.hash;
    }else if(task.type === "encrypt"){
        single_task_title.textContent = "文件对称加密";
        single_task_info.textContent = task.config;
    }else if(task.type === "decrypt"){
        single_task_title.textContent = "文件对称解密";
        single_task_info.textContent = task.config;
    }
    let single_task_status = document.createElement("div");
    single_task_status.className = "single_task_status";
    single_task_status.textContent = "等待";
    single_task_area.appendChild(single_task_title);
    single_task_area.appendChild(single_task_info);
    single_task_area.appendChild(single_task_status);
    let waitting_task_list = document.getElementById("waitting_task_list");
    waitting_task_list.appendChild(single_task_area);
}
function addRunningTask(task){
    let single_task_area = document.createElement("div");
    single_task_area.dataset.info = JSON.stringify(task);
    single_task_area.className = "single_task_area";
    single_task_area.dataset.id = task.id;
    let single_task_title = document.createElement("div");
    single_task_title.className = "single_task_title";
    let single_task_info = document.createElement("div");
    single_task_info.className = "single_task_info";
    if(task.type === "hash"){
        single_task_title.textContent = "文件散列计算";
        single_task_info.textContent = task.hash;
    }else if(task.type === "encrypt"){
        single_task_title.textContent = "文件对称加密";
        single_task_info.textContent = task.config;
    }else if(task.type === "decrypt"){
        single_task_title.textContent = "文件对称解密";
        single_task_info.textContent = task.config;
    }
    let single_task_status = document.createElement("div");
    single_task_status.className = "single_task_status";
    if(task.status === 0){
        single_task_status.textContent = "运行";
    }else if(task.status === 1){
        single_task_status.textContent = "暂停";
    }else if(task.status === 2){
        single_task_status.textContent = "完成";
    }
    single_task_area.appendChild(single_task_title);
    single_task_area.appendChild(single_task_info);
    single_task_area.appendChild(single_task_status);
   let single_task_progress_field = document.createElement("div");
   single_task_progress_field.className = "single_task_progress_field";
   let single_task_progress = document.createElement("div");
   single_task_progress.className = "single_task_progress";
   single_task_progress.dataset.id = task.id;
   single_task_progress.style.width = (task.progress*100+"").substring(0,5)+"%";
   let single_task_progress_label = document.createElement("div");
   single_task_progress_label.className = "single_task_progress_label";
   single_task_progress_label.dataset.id = task.id;
   single_task_progress_label.textContent = (task.progress*100+"").substring(0,5)+"%";
   single_task_progress_field.appendChild(single_task_progress);
   single_task_progress_field.appendChild(single_task_progress_label);
   single_task_area.appendChild(single_task_progress_field);
   let single_task_test = document.createElement("div");
   single_task_test.className = "single_task_test";
   single_task_test.textContent = "剩余:"+fmtTime(Math.floor(task.time/task.progress-task.time));
   single_task_area.appendChild(single_task_test);
   let single_task_cost = document.createElement("div");
   single_task_cost.className = "single_task_cost";
   single_task_cost.textContent = "耗时:"+fmtTime(task.time);
   single_task_area.appendChild(single_task_cost);
   let single_task_operation = document.createElement("div");
   single_task_operation.className = "single_task_operation";
   let single_task_pause_btn = document.createElement("div");
   single_task_pause_btn.className = "single_task_pause_btn";
   single_task_pause_btn.textContent = "暂停";
   single_task_pause_btn.addEventListener("click",()=>{
       window.taskBridge.pause_task(JSON.stringify({id:task.id}));
   });
   single_task_operation.appendChild(single_task_pause_btn);
   let single_task_stop_btn = document.createElement("div");
   single_task_stop_btn.className = "single_task_stop_btn";
   single_task_stop_btn.textContent = "停止";
   single_task_stop_btn.addEventListener("click",()=>{
       window.taskBridge.stop_task(JSON.stringify({id:task.id}));
   })
   single_task_operation.appendChild(single_task_stop_btn);
   single_task_area.appendChild(single_task_operation);
   single_task_area.addEventListener("click",(event)=>{
        showInfo(single_task_area.dataset.info);
   })
   let running_task_list = document.getElementById("running_task_list");
   running_task_list.appendChild(single_task_area);
}
function updateRunningTask(task){
    let single_task_area = document.querySelector(`.single_task_area[data-id='${task.id}']`);
    single_task_area.dataset.info = JSON.stringify(task); 
    let single_task_status = document.querySelector(`.single_task_area[data-id='${task.id}'] .single_task_status`);
    let single_task_progress = document.querySelector(`.single_task_area[data-id='${task.id}'] .single_task_progress`);
    let single_task_progress_label = document.querySelector(`.single_task_area[data-id='${task.id}'] .single_task_progress_label`);
    let single_task_cost = document.querySelector(`.single_task_area[data-id='${task.id}'] .single_task_cost`);
    let single_task_operation = document.querySelector(`.single_task_area[data-id='${task.id}'] .single_task_operation`);
    let single_task_test = document.querySelector(`.single_task_area[data-id='${task.id}'] .single_task_test`);
    let single_task_pause_btn = document.querySelector(`.single_task_area[data-id='${task.id}'] .single_task_pause_btn`);

    if(task.status === 0){
        single_task_status.textContent = "运行";
        single_task_pause_btn.removeEventListener("click",()=>{
            window.taskBridge.resume_task(JSON.stringify({id:task.id}));
        })
        single_task_pause_btn.textContent = "暂停";
        single_task_pause_btn.addEventListener("click",()=>{
            window.taskBridge.pause_task(JSON.stringify({id:task.id}));
        });
    }else if(task.status === 1){
        single_task_status.textContent = "暂停";
        single_task_pause_btn.removeEventListener("click",()=>{
            window.taskBridge.pause_task(JSON.stringify({id:task.id}));
        })
        single_task_pause_btn.textContent = "继续";
        single_task_pause_btn.addEventListener("click",()=>{
            window.taskBridge.resume_task(JSON.stringify({id:task.id}));
        });
    }else if(task.status === 2){
        single_task_status.textContent = "完成";
        while(single_task_operation.firstChild){
            single_task_operation.removeChild(single_task_operation.firstChild);
        }
    }
    single_task_progress.style.width = (task.progress*100+"").substring(0,5)+"%";
    single_task_progress_label.textContent = (task.progress*100+"").substring(0,5)+"%";
    single_task_cost.textContent = "耗时:"+fmtTime(task.time);
    single_task_test.textContent = "剩余:"+fmtTime(Math.floor(task.time/task.progress-task.time));
}

function updateRunning(result){
    if(result.length !== 0){
        console.log(result);
    }
    result.forEach((task)=>{
        if(!running_id.has(task.id)){
            addRunningTask(task);
            running_id.add(task.id);
        }else{
            updateRunningTask(task);
        }
    })
}
function updateWaitting(result){
    let tmp_waitting_id = [];
    result.forEach((task)=>{
        tmp_waitting_id.push(task.id);
    })
    let ready_add = tmp_waitting_id.filter(item => !waitting_id.includes(item));
    let ready_remove = waitting_id.filter(item => !tmp_waitting_id.includes(item));
    result.forEach((task)=>{
        if(ready_add.includes(task.id)){
            addWaittingTask(task);
        }
    })
    ready_remove.forEach((id)=>{
        let single_task_area = document.querySelector(`.single_task_area[data-id='${id}']`);
        single_task_area.remove();
    })
    waitting_id = tmp_waitting_id;
}
