$(document).ready(function(){
    console.log("Get Ready !")
})

$("#btn-deploy").click(function(e){
    var condition1 = $("#pentest-type").val()
    var condition2 = $("#attack-type").val()
    if(condition1 == "scan"){
        e.preventDefault();
        ScanConfig(condition2);
    } 
    else if(condition1 == "flood"){
        console.log("Flood")
    }
    else if(condition1 == "poison"){
        console.log("Poison")
    }
    else{
        console.log("Choose pentest type")

    }
})

function ScanConfig(scan_type){
    $.ajax({
        type: "POST",
        url: "/pentest/scan",
        dataType: "json",
        contentType: "application/json",
        data: JSON.stringify({
            type : scan_type,
            src_ip : $("#inp-scan-src-ip").val(),
            dst_ip : $("#inp-scan-dst-ip").val(),
            min_port : $("#inp-scan-min-port").val(),
            max_port : $("#inp-scan-max-port").val(),
            thread : $("#inp-scan-thrd").val(),
            delay : $("#inp-scan-delay").val()
        }), 
        success: function(){
            console.log("success")
        },
        error: function(){
            console.log("Error!")
        }
    });
    console.log("Button scan click!")
}