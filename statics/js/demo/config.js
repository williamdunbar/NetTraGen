$(document).ready(function(){
    console.log("Get Ready !")
})

$(".btn-deploy").click(function(e){
    var condition1 = $("#pentest-type").val()
    var condition2 = $("#attack-type").val()
    e.preventDefault();
    if(condition1 == "scan"){
        console.log("Scan")
        ScanConfig(condition2);
    } 
    else if(condition1 == 'flood'){
        console.log("Flood")  
        FloodConfig(condition2);
    }
    else if(condition1 == 'poison'){
        console.log("Poison")
        ArpConfig(); 
    }
    else{
        console.log("Choose pentest type")

    }
    
})

function clear(){
    console.log("Clear");
}

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
            window.location.replace("/result/scan")        
        },
        error: function(){
            console.log("Error!")
            window.location.replace("/result/scan")            
        }
    });
    console.log("Button scan click!")
}

function FloodConfig(flood_type){
    $.ajax({
        type: "POST",
        url: "/pentest/flood",
        dataType: "json",
        contentType: "application/json",
        data: JSON.stringify({
            src_ip : $("#dst_IP").val(),
            dst_port : $("#dst_port").val(),
            delay : $("#delay").val(),
            thread : $("#thread").val()
        }), 
        success: function(){
            console.log("Success")
            window.location.replace("/result/flood")        
        },
        error: function(){
            console.log("Error!")
            window.location.replace("/result/flood")            
        }
    });
    console.log("Button flood click!")
}

function ArpConfig(){
    $.ajax({
        type: "POST",
        url: "/pentest/arp",
        dataType: "json",
        contentType: "application/json",
        data: JSON.stringify({
            at_mac : $("#at_mac").val(),
            vt_mac : $("#vt_mac").val(),
            gw_mac : $("#gw_mac").val(),
            vt_ip : $("#vt_ip").val(),
            gw_ip : $("#gw_ip").val()          
        }), 
        success: function(){
            console.log("success")
            window.location.replace("/result/arp")        
        },
        error: function(){
            console.log("Error!")
            window.location.replace("/result/arp")            
        }
    });
    console.log("Button scan click!")
}