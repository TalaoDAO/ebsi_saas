from flask import  request, render_template, redirect, session, jsonify
import json
import logging
import copy
import db_api 
from urllib.parse import urlencode
import uuid
from ebsi_constante import ebsi_vc_type_list, landing_page_style_list, ebsi_credential_to_issue_list
import ebsi

logging.basicConfig(level=logging.INFO)

def init_app(app,red, mode) :
    app.add_url_rule('/ebsi/issuer/console/logout',  view_func=ebsi_nav_logout, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/issuer/console',  view_func=ebsi_issuer_console, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/ebsi/issuer/console/select',  view_func=ebsi_issuer_select, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/issuer/console/advanced',  view_func=ebsi_issuer_advanced, methods = ['GET', 'POST'])
    app.add_url_rule('/ebsi/issuer/console/preview',  view_func=ebsi_issuer_preview, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/ebsi/issuer/preview_presentation/<stream_id>',  view_func=ebsi_issuer_preview_presentation_endpoint, methods = ['GET', 'POST'],  defaults={'red' : red})
    # nav bar option
    app.add_url_rule('/ebsi/issuer/nav/logout',  view_func=ebsi_nav_logout, methods = ['GET'])
    app.add_url_rule('/ebsi/issuer/nav/create',  view_func=ebsi_nav_create, methods = ['GET'], defaults= {'mode' : mode})
    return
    

def ebsi_nav_logout() :
    session.clear()
    return redirect ('/ebsi/saas4ssi')


def ebsi_issuer_select() :
    if not session.get('is_connected')  :
        return redirect('/ebsi/saas4ssi')
    if request.method == 'GET' :  
        my_list = db_api.list_ebsi_issuer()
        issuer_list=str()
        for data in my_list :
            data_dict = json.loads(data)         
            client_id = data_dict['client_id']
            DID = data_dict['did_ebsi']
            issuer = """<tr>
                        <td>""" + data_dict.get('application_name', "unknown") + """</td>
                        <td><a href=/ebsi/issuer/console?client_id=""" + data_dict['client_id'] + """>""" + data_dict['client_id'] + """</a></td>
                        <td>""" + DID[:10] +'....' + DID[-10:] + """</td> 
                        <td>""" + ebsi_credential_to_issue_list.get(data_dict['credential_to_issue'], 'unknown') + """</td>
                        </tr>"""
            issuer_list += issuer
        return render_template('ebsi/ebsi_issuer_select.html', issuer_list=issuer_list) 
   
       
def ebsi_nav_create(mode) :
    if not session.get('is_connected') :
        return redirect('/ebsi/saas4ssi')
    return redirect('/ebsi/issuer/console?client_id=' + db_api.create_ebsi_issuer(mode))


def ebsi_issuer_preview (mode) :
    if not session.get('is_connected') :
        return redirect('/ebsi/saas4ssi')
    stream_id = str(uuid.uuid1())
    client_id = session['client_data']['client_id']
    issuer_data = json.loads(db_api.read_ebsi_issuer(client_id))
    qrcode_message = issuer_data.get('qrcode_message', "No message")
    mobile_message = issuer_data.get('mobile_message', "No message")
    if not issuer_data.get('landing_page_style') :
        qrcode_page = "ebsi/ebsi_issuer_qrcode_2.html"
    else : 
        qrcode_page = issuer_data.get('landing_page_style')  
    url = mode.server + 'issuer/preview_presentation/' + stream_id
    deeplink_talao = mode.deeplink_talao + 'app/download?' + urlencode({'uri' : url })
    deeplink_altme = mode.deeplink_altme + 'app/download?' + urlencode({'uri' : url})
    return render_template(qrcode_page,
							url=url,
                            deeplink_talao=deeplink_talao,
                            deeplink_altme=deeplink_altme,
							stream_id=stream_id,
                            qrcode_message=qrcode_message,
                            mobile_message=mobile_message,
                            landing_page_url= issuer_data['landing_page_url'],
                            title=issuer_data['title'],
                            page_title=issuer_data['page_title'],
                            page_subtitle=issuer_data['page_subtitle'],
                            page_description=issuer_data['page_description'],
                            terms_url= issuer_data.get('terms_url'),
                            privacy_url=issuer_data.get('privacy_url'),
                            back_button = True,
                            page_background_color = issuer_data['page_background_color'],
                            page_text_color = issuer_data['page_text_color'],
                            qrcode_background_color = issuer_data['qrcode_background_color'],
                            )
    
def ebsi_issuer_preview_presentation_endpoint(stream_id, red):
    if request.method == 'GET':
        try :
            my_pattern = json.loads(red.get(stream_id).decode())['pattern']
        except :
            logging.error('red decode failed')
            red.set(stream_id + '_access',  'server_error')
            red.publish('login', json.dumps({"stream_id" : stream_id}))
            return jsonify("server error"), 500
        return jsonify(my_pattern)


def ebsi_issuer_console(mode) :
    global  reason
    if not session.get('is_connected') :
        return redirect('/ebsi/saas4ssi')
    if request.method == 'GET' :
        if not request.args.get('client_id') :
            return redirect('/ebsi/issuer/console/select')
        else  :
            session['client_id'] = request.args.get('client_id')
        session['client_data'] = json.loads(db_api.read_ebsi_issuer(session['client_id']))
      
        landing_page_style_select = str()
        for key, value in landing_page_style_list.items() :
                if key == session['client_data'].get('landing_page_style') :
                    landing_page_style_select +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    landing_page_style_select +=  "<option value=" + key + ">" + value + "</option>"
      
        # cedential to usse for EBSI issuer
        credential_items = ebsi_credential_to_issue_list.items()
        credential_to_issue_select = str()
        for key, value in credential_items :
                if key ==   session['client_data']['credential_to_issue'] :
                    credential_to_issue_select +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    credential_to_issue_select +=  "<option value=" + key + ">" + value + "</option>"
        return render_template('ebsi/ebsi_issuer_console.html',
                application_name=session['client_data'].get('application_name', 'Unknown'),
                client_secret=session['client_data']['client_secret'],
                callback=session['client_data']['callback'],
                issuer_landing_page = session['client_data']['issuer_landing_page'],
                title = session['client_data'].get('title'),
                privacy_url = session['client_data'].get('privacy_url'),
                landing_page_url = session['client_data'].get('landing_page_url'),
                terms_url = session['client_data'].get('terms_url'),
                client_id= session['client_data']['client_id'],
                company_name = session['client_data']['company_name'],
                page_title = session['client_data']['page_title'],
                note = session['client_data']['note'],
                page_subtitle = session['client_data']['page_subtitle'],
                page_description = session['client_data']['page_description'],
                qrcode_message = session['client_data'].get('qrcode_message', ""),
                mobile_message = session['client_data'].get('mobile_message', ""),
                credential_to_issue_select = credential_to_issue_select,
                landing_page_style_select =  landing_page_style_select,
                page_background_color = session['client_data']['page_background_color'],
                page_text_color = session['client_data']['page_text_color'],
                qrcode_background_color = session['client_data']['qrcode_background_color'],
                )
    if request.method == 'POST' :
        if request.form['button'] == "delete" :
            db_api.delete_ebsi_issuer( request.form['client_id'])
            return redirect ('/ebsi/issuer/console')
        
        else :
            session['client_data']['callback'] = request.form['callback']
            #session['client_data']['secret'] = request.form['secret']
            session['client_data']['landing_page_style'] = request.form['landing_page_style']
            session['client_data']['page_title'] = request.form['page_title']
            session['client_data']['page_subtitle'] = request.form['page_subtitle']
            session['client_data']['page_description'] = request.form['page_description']
            session['client_data']['note'] = request.form['note']          
            session['client_data']['title'] = request.form['title']
            session['client_data']['privacy_url'] = request.form['privacy_url']
            session['client_data']['landing_page_url'] = request.form['landing_page_url']
            session['client_data']['terms_url'] = request.form['terms_url']
            session['client_data']['client_id'] =  request.form['client_id']
            session['client_data']['company_name'] = request.form['company_name']
            session['client_data']['application_name'] = request.form['application_name']
            session['client_data']['credential_to_issue'] = request.form['credential_to_issue']
            #session['client_data']['credential_to_issue_2'] = request.form['credential_to_issue_2']
            session['client_data']['qrcode_message'] = request.form['qrcode_message']
            session['client_data']['mobile_message'] = request.form['mobile_message'] 
            session['client_data']['page_background_color'] = request.form['page_background_color']      
            session['client_data']['page_text_color'] = request.form['page_text_color']  
            session['client_data']['qrcode_background_color'] = request.form['qrcode_background_color']    
              
            if request.form['button'] == "preview" :
                return redirect ('/ebsi/issuer/console/preview')

            if request.form['button'] == "advanced" :
                return redirect ('/ebsi/issuer/console/advanced')
            
            if request.form['button'] == "update" :
                db_api.update_ebsi_issuer(request.form['client_id'], json.dumps(session['client_data']))
                return redirect('/ebsi/issuer/console?client_id=' + request.form['client_id'])

            if request.form['button'] == "copy" :
                new_client_id=  db_api.create_ebsi_issuer(mode)
                new_data = copy.deepcopy(session['client_data'])
                new_data['application_name'] = new_data['application_name'] + ' (copie)'
                new_data['client_id'] = new_client_id
                db_api.update_ebsi_issuer(new_client_id, json.dumps(new_data))
                return redirect('/ebsi/issuer/console?client_id=' + new_client_id)


async def ebsi_issuer_advanced() :
    global  reason
    if not session.get('is_connected') :
        return redirect('/ebsi/saas4ssi')
    if request.method == 'GET' :
        session['client_data'] = json.loads(db_api.read_ebsi_issuer(session['client_id']))
        ebsi_vc_type_select = str()       
        for key, value in ebsi_vc_type_list.items() :
                if key ==   session['client_data'].get('ebsi_issuer_vc_type', "jwt_vc") :
                    ebsi_vc_type_select +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    ebsi_vc_type_select +=  "<option value=" + key + ">" + value + "</option>"

        did_ebsi = session['client_data']['did_ebsi']
        did_document = ebsi.did_resolve(did_ebsi, session['client_data']['jwk'])
        jwk = json.dumps(json.loads(session['client_data']['jwk']), indent=4)
        did_ebsi = session['client_data']['did_ebsi']
        return render_template('ebsi/ebsi_issuer_advanced.html',
                client_id = session['client_data']['client_id'],
                jwk = jwk,
                ebsi_vc_type_select=ebsi_vc_type_select,
                did_ebsi = did_ebsi,
                did_document=json.dumps(json.loads(did_document), indent=4)
                )
    if request.method == 'POST' :        
        if request.form['button'] == "back" :
            return redirect('/ebsi/issuer/console?client_id=' + request.form['client_id'])

        if request.form['button'] == "update" :
            session['client_data']['ebsi_issuer_vc_type'] = request.form['ebsi_issuer_vc_type']
            jwk_dict = json.loads(session['client_data']['jwk'])
            session['client_data']['jwk'] = json.dumps(jwk_dict)
            session['client_data']['did_ebsi'] = request.form['did_ebsi']
            db_api.update_ebsi_issuer( request.form['client_id'], json.dumps(session['client_data']))
            return redirect('/ebsi/issuer/console/advanced')
          