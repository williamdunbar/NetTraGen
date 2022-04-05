$(document).ready(function(){
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
        
    });
});