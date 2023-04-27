from rest_framework.authentication import BaseAuthentication
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed
class IsCustomer(BaseAuthentication):
 def authenticate(self, request):
  username = request.GET.get('username')
  if username is None:
   return None
  try:
   user = User.objects.get(username=username)
   try:
     user.is_customer
     return (user, None)
   except:
    raise AuthenticationFailed('you are not registered as customer')
  except User.DoesNotExist:
   raise AuthenticationFailed('No Such User')
  
# class Custom(BasicAuthentication):
#      def authenticate_credentials(self, userid, password, request=None):
#         """
#         Authenticate the userid and password against username and password
#         with optional request for context.
#         """
#         credentials = {
#             get_user_model().USERNAME_FIELD: userid,
#             'password': password
#         }
#         user = authenticate(request=request, **credentials)

#         if user is None:
#             raise AuthenticationFailed(_('Invalid username/password.'))

#         if not user.is_active:
#             raise AuthenticationFailed(_('User inactive or deleted.'))

#         return (user, None)