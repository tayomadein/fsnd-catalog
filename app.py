''' Catalog App '''
import random
import string
import json
import httplib2
import requests
from database_setup import Base, User, Category, Item
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from flask import session as login_session, make_response
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import Flask, render_template, request, redirect
from flask import url_for, jsonify, flash

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secret.json', 'r').read())[
    'web']['client_id']

# Create session and connect to DB
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to prevent request forgery.
# Store it in the session for later validation


@app.route('/')
# shows a list of all categories
def showHome():
    ''' Handle home page '''
    categories = session.query(Category).order_by(asc(Category.name))
    latest_items = session.query(Item).order_by(
        asc(Item.date_created)).all()[:10]
    login = 'username' in login_session
    return render_template('index.html', login=login,
                               categories=categories,
                               latest_items=latest_items)


@app.route('/login')
def showLogin():
    ''' Handle login for app '''
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" %login_session['state']
    return render_template('login.html', STATE=state)

# CONNECT - Set a user's login_session

# Google Login


@app.route('/gconnect', methods=['POST'])
def gconnect():
    ''' Handle login by connecting via Google auth API '''
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Ugrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that accesss token is valid
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # IF there was an error in the access token info, abort mission!
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
    # Verify that the access token is used for the intended user.response
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's users ID doesn't match given user ID"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token's client ID doesn't match given app's ID."), 401)
        print "Token's client ID doesn't match given app's ID."
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check to see if user is already logged in
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            "User is currently logged in"), 200)
        response.headers['Content-Type'] = 'application/json'

    # Store the access token in the session for later use
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if not create a new user
    user_id = getUserID(login_session["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img class="avatar" src="'
    output += login_session['picture']
    output += ' "> '
    flash("Welcome, %s" % login_session['username'])
    print "done!"
    return output

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    ''' Disconnect from google '''
    # Only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('User is not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    # Execute HTTP GET request to revoke current token.
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    # Handle result
    print 'result is '
    print result
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # If the token is invalid
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# FB Login


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    ''' Handle authentication by connecting with facebook '''
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token
    app_id = json.loads(open('fb_client_secret.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secret.json', 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type='
           'fb_exchange_token&client_id=%s&client_secret=%s&'
           'fb_exchange_token=%s') % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.12/me"
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = ('https://graph.facebook.com/v2.12/me?access_token=%s&fields'
           '=name,id,email') % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = ('https://graph.facebook.com/v2.12/me/picture?access_token=%s'
           '&redirect=0&height=200&width=200') % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " class="avatar"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    ''' Disconnect from facebook'''
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/logout')
def logout():
    ''' Handle logout from multiple providers'''
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showHome'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showHome'))


# JSON APIs for catalog


@app.route('/catalog/JSON')
def catalogJSON():
    ''' Return all items in the catalog '''
    catalog = session.query(Item).all()
    return jsonify(Catalog=[i.serialize for i in catalog])


@app.route('/category/<int:cat_id>/JSON')
def categoryJSON(cat_id):
    ''' Return all items in a category '''
    items = session.query(Item).filter_by(cat_id=cat_id).all()
    return jsonify(categoryItems=[i.serialize for i in items])


@app.route('/item/<int:item_id>/JSON')
def itemJSON(item_id):
    ''' Return details about one item '''
    item = session.query(Item).filter_by(item_id=item_id).one()
    return jsonify(Item=item.serialize)

# Handle Catalog


@app.route('/category/<int:cat_id>/items')
def showCategory(cat_id):
    ''' Show all items in a category '''
    # categories = session.query(Category).all()
    cat_name = session.query(Category).filter_by(cat_id=cat_id).one().name
    items = session.query(Item).filter_by(cat_id=cat_id)
    login = 'username' in login_session
    return render_template('category.html',  login, items=items,
                               cat_name=cat_name, cat_id=cat_id)


@app.route('/category/<int:cat_id>/<int:item_id>')
def showItem(cat_id, item_id):
    ''' Show all details about an item '''
    cat_name = session.query(Category).filter_by(cat_id=cat_id).one().name
    item = session.query(Item).filter_by(item_id=item_id).one()
    login = 'username' in login_session
    return render_template('item.html', login=login, item=item,
                               cat_name=cat_name)


@app.route('/category/add', methods=['GET', 'POST'])
def newCategory():
    ''' Create a new category'''
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('%s has successfully created category %s' %
              (login_session['username'], newCategory.name))
        session.commit()
        return redirect(url_for('showHome'))
    else:
        return render_template('newcategory.html')


@app.route('/category/item/add', methods=['GET', 'POST'])
def newItem():
    ''' Create a new item in a category '''
    if 'username' not in login_session:
        return redirect('/login')
    else:
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            cat_id = request.form['category']
            print cat_id
            newItem = Item(name=name, description=description, cat_id=cat_id,
                           user_id=login_session['user_id'])
            session.add(newItem)
            session.commit()
            return redirect(url_for('showHome'))
        else:
            categories = session.query(Category).all()
            return render_template('newitem.html', categories=categories)


@app.route('/category/<int:cat_id>/edit', methods=['GET', 'POST'])
def editCategory(cat_id):
    ''' Edit a category '''
    edit_category = session.query(Category).filter_by(cat_id=cat_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if edit_category.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are not authorized"
                "to edit this category. Please create your own category in "
                "order to edit.');window.location.href = '/';}</script><body"
                " onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name']:
            edit_category.name = request.form['name']
        flash('%s has successfully updated %s category' %
              (login_session['username'], edit_category.name))
        session.commit()
        return redirect(url_for('showCategory', cat_id=cat_id))
    else:
        return render_template('editcategory.html', category=edit_category)


@app.route('/category/<int:cat_id>/delete', methods=['GET', 'POST'])
def deleteCategory(cat_id):
    ''' Delete a Category '''
    delete_category = session.query(Category).filter_by(cat_id=cat_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if delete_category.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are not authorized"
                "to delete this category. Please create your own category in "
                "order to delete.');window.location.href = '/';}</script><body"
                " onload='myFunction()''>")
    if request.method == 'POST':
        session.delete(delete_category)
        flash('%s has successfully deleted category %s' %
              (login_session['username'], delete_category.name))
        session.commit()
        return redirect(url_for('showHome'))
    else:
        return render_template('deletecategory.html', category=delete_category)


@app.route('/category/<int:cat_id>/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(cat_id, item_id):
    ''' Edit an Item '''
    edit_item = session.query(Item).filter_by(item_id=item_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if edit_item.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are not authorized"
                "to edit this item. Please create your own item in "
                "order to edit.');window.location.href = '/';}</script><body"
                " onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name']:
            edit_item.name = request.form['name']
        if request.form['description']:
            edit_item.description = request.form['description']
        if request.form['category']:
            edit_item.cat_id = request.form['category']
        session.add(edit_item)
        flash('%s has successfully editted item %s' %
              (login_session['username'], edit_item.name))
        session.commit()
        return redirect(url_for('showItem', cat_id=cat_id, item_id=item_id))
    else:
        categories = session.query(Category).all()
        return render_template('edititem.html', item=edit_item,
                               categories=categories)


@app.route('/category/<int:cat_id>/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(cat_id, item_id):
    ''' Delete an Item '''
    delete_item = session.query(Item).filter_by(item_id=item_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if delete_item.user_id != login_session['user_id']:
        return ("<script>function myFunction() {alert('You are not authorized"
                "to delete this item. Please create your own item in "
                "order to delete.'); window.location.href = '/';}</script><body"
                " onload='myFunction()''>")
    if request.method == 'POST':
        session.delete(delete_item)
        flash('%s has successfully deleted item %s' %
              (login_session['username'], delete_item.name))
        session.commit()
        return redirect(url_for('showCategory', cat_id=cat_id))
    else:
        return render_template('deleteitem.html', item=delete_item)


@app.errorhandler(404)
def notFound(e):
    ''' Handle pages/URLs that don't exist '''
    return render_template('404.html'), 404

# Helper funtions for creating user


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.user_id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.user_id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'my_super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
