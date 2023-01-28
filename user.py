import asyncio

from sqlalchemy import asc, desc, and_, or_

from common import web, jsonify, login_required, encrypt_data, decrypt_data, rollbar
from config import Config
from error import Error
from mail import send_mail_html
from schemes import sign_in_schema

from db import (
    Session, 
    get_slave_session,
    User,
    Profile,
    City
)

routes = web.RouteTableDef()

@routes.post('/v1/user/signin')
async def user_signin(request):
    '''
    User signin '''
    data = await request.json()

    res = sign_in_schema.validate(data)
    if not res:
        return jsonify(status='error', message=sign_in_schema.errors)

    email    = data.get('email', None)
    password = data.get('password', None)

    if None in [email, password]:
        error = Error(12)
        return jsonify(status='error', message=error)

    session = get_slave_session()

    ## get user and profile
    try:
        q = session.query(User, Profile)
        q = q.filter(User.uid==Profile.user_uid)
        q = q.filter(User.email==email)
        user, profile = q.one()
    except Exception as e:
        session.close()
        rollbar.report_exc_info()
        error = Error(13)
        return jsonify(status='error', message=error)

    if user and not user.check_password(password):
        session.close()
        error = Error(13)
        return jsonify(status='error', message=error)

    user_dict = user.to_dict(clean=True)
    profile_dict = profile.to_dict(clean=True)

    session.close()

    del user_dict['password']
    secret = encrypt_data(user_dict)

    response = {
        'user': user_dict,
        'profile': profile_dict,
        'secret': secret
    }

    return jsonify(status='success', response=response)

@routes.post('/v1/user/signup')
async def user_signup(request):
    '''
    User signup '''
    data = await request.json()

    email        = data.get('email', None)
    password     = data.get('password', None)

    if None in [email, password]:
        error = Error(10)
        return jsonify(status='error', message=error)

    session = Session()

    ## create user
    try:
        user = User.create_user(
            session,
            email=email,
            password=password,
        )
    except Exception as e:
        session.rollback()
        session.close()
        rollbar.report_exc_info()
        error = Error(11)
        return jsonify(status='error', message=error)

    ## create profile
    try:
        profile = Profile.create_profile(
            session=session,
            user_uid=user.uid,
        )
    except Exception as e:
        session.rollback()
        session.close()
        rollbar.report_exc_info()
        error = Error(1)
        return jsonify(status='error', message=error)

    user_dict = user.to_dict(clean=True)
    profile_dict = profile.to_dict(clean=True)

    try:
        session.commit()
    except:
        session.rollback()
        rollbar.report_exc_info()
        raise
    finally:
        session.close()

    del user_dict['password']
    secret = encrypt_data(user_dict)

    response = {
        'user': user_dict,
        'profile': profile_dict,
        'secret': secret
    }

    '''
    async def async_send_mail(future, data_dict):
        try:
            send_mail(
                Config.noreply_email,
                data_dict['email'],
                '{} - Please Verify Your Account'.format(Config.title),
                '\n'.join([
                    "Thanks for using {}! Please confirm your email address by clicking on the link below. We'll communicate with you from time to time via email so it's important that we have an up-to-date email address on file.".format(Config.title),
                    '',
                    '{}/v1/user/verify/{}'.format(Config.url, data_dict['uid']),
                    '',
                    'Enjoy our service!',
                    Config.title,
                ])
            )
        except Exception as e:
            rollbar.report_exc_info()
            print(e)

    data_dict = {}
    data_dict['email'] = user_dict['email']
    data_dict['uid'] = user_dict['uid']
    data_dict['username'] = user_dict['username']

    # background mail send
    future = asyncio.Future()
    asyncio.ensure_future(async_send_mail(future, data_dict))
    '''

    return jsonify(status='success', response=response)

@routes.post('/v1/user/recover')
async def user_recover(request):
    '''
    User send recover email '''
    data = await request.json()

    email = data.get('email', None)

    if None in [email]:
        error = Error(12)
        return jsonify(status='error', message=error)

    session = get_slave_session()

    ## get user and profile
    try:
        q = session.query(User, Profile)
        q = q.filter(User.uid==Profile.user_uid)
        q = q.filter(User.email==email)
        user, profile = q.one()
    except Exception as e:
        session.close()
        rollbar.report_exc_info()
        error = Error(13)
        return jsonify(status='error', message=error)

    user_dict = user.to_dict(clean=True)
    profile_dict = profile.to_dict(clean=True)

    session.close()

    # # create mail
    # mail = send_mail_html(
    #     Config.noreply_email,
    #     user_dict['email'],
    #     f'Reset password',
    #     reset_password_tpl.format(
    #         Config.url,
    #         user_dict['email'],
    #         recover_url,
    #     )
    # )

    # # async send mail from future
    # asyncio.ensure_future(mail)

    response = {}

    return jsonify(status='success', response=response)

@routes.post('/v1/user/reset')
async def user_recover(request):
    '''
    User reset password '''
    data = await request.json()

    secret   = data.get('secret', None)
    password = data.get('password', None)

    if None in [secret, password]:
        error = Error(12)
        return jsonify(status='error', message=error)

    ## decrypt secret
    try:
        user_dict = decrypt_data(secret)
    except Exception as e:
        error = Error(12)
        return jsonify(status='error', message=error)

    session = get_slave_session()

    ## get user and profile
    try:
        q = session.query(User, Profile)
        q = q.filter(User.uid==Profile.user_uid)
        q = q.filter(User.uid==user_dict['uid'])
        user, profile = q.one()
    except Exception as e:
        session.close()
        rollbar.report_exc_info()
        error = Error(13)
        return jsonify(status='error', message=error)

    ## update password
    user.change_password(session, password=password)

    try:
        session.commit()
    except:
        session.rollback()
        rollbar.report_exc_info()
        raise
    finally:
        session.close()

    response = {}

    return jsonify(status='success', response=response)

@routes.post('/v1/profile/get')
@login_required()
async def user_get(request):
    '''
    User get '''
    user_dict = request.user

    session = get_slave_session()

    try:
        profile = Profile.get_profile(
            session,
            user_uid=user_dict['uid'],
        )
    except Exception as e:
        session.close()
        rollbar.report_exc_info()
        error = Error(2)
        return jsonify(status='error', message=error)

    profile_dict = profile.to_dict(clean=True)

    session.close()

    response = {
        'user': user_dict,
        'profile': profile_dict,
    }

    return jsonify(status='success', response=response)

@routes.post('/v1/profile/update')
@login_required()
async def user_update(request):
    '''
    User update'''
    user_dict = request.user
    data = await request.json()

    password     = data.get('password', None)
    first_name   = data.get('first_name', None)
    last_name    = data.get('last_name', None)
    phone_number = data.get('phone_number', None)
    address      = data.get('address', None)
    city_code    = data.get('city_code', None)
    settings     = data.get('settings', None)

    session = Session()

    ## get user and profile
    try:
        q = session.query(User, Profile)
        q = q.filter(User.uid==Profile.user_uid)
        q = q.filter(User.uid==user_dict['uid'])
        user, profile = q.one()
    except Exception as e:
        session.close()
        rollbar.report_exc_info()
        error = Error(13)
        return jsonify(status='error', message=error)

    if password and password is not None:
        user.change_password(session, password)

    profile_dict = {}

    if first_name and first_name is not None:
        profile_dict['first_name'] = first_name

    if last_name and last_name is not None:
        profile_dict['last_name'] = last_name

    if phone_number and phone_number is not None:
        profile_dict['phone_number'] = phone_number

    if address and address is not None:
        profile_dict['address'] = address

    if city_code and city_code is not None:
        profile_dict['city_code'] = city_code

    if settings and settings is not None:
        profile_dict['settings'] = settings

    profile.update_profile(session, **profile_dict)

    user_dict = user.to_dict(clean=True)
    del user_dict['password']
    profile_dict = profile.to_dict(clean=True)

    try:
        session.commit()
    except:
        session.rollback()
        rollbar.report_exc_info()
        raise
    finally:
        session.close()

    response = {
        'user': user_dict,
        'profile': profile_dict,
    }

    return jsonify(status='success', response=response)
