from flask import Blueprint,request,jsonify
from controllers.scan_controller import scan

scan_router=Blueprint("scan_router",__name__)


@scan_router.route("/scan",methods=["POST"])
def run_scan():
    
    data=request.json
    
    target=data.get("target")
    mode=data.get("mode")
    
    if not target or not mode:
        return jsonify({
            "error":"Missing requirement"
        }),400
        
        
    try:
        table,stats,terminal=scan(target,mode)
        return jsonify({
            "target":target,
            "mode":mode,
            "table":table,
            "stats":stats,
            "terminal":terminal
        })
    except Exception as e:
        return jsonify({
            "error":str(e)
        }),500