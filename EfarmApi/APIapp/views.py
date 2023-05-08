from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from .models import *
from .serializers import *
from django.db import IntegrityError
from .serializers import UserSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly
from django.contrib.auth import authenticate, login
from .serializers import UserSerializer
from rest_framework import generics, permissions, authentication
from rest_framework import status, views
from rest_framework import viewsets
# from .customauth import IsCustomer
from django.db.models import Q
from django.contrib.auth import get_user_model,logout
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from .serializers import ForgotPasswordSerializer
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model, login
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import render
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model, authenticate




from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

User = get_user_model() 
class UserRegistrationAPI(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer
    def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                print("before",serializer.validated_data)
                password = serializer.validated_data.pop('password')
                print(password)
                confirm_password = serializer.validated_data.pop('confirm_password')
                print(confirm_password)
                print("After",serializer.validated_data)
                if password != confirm_password:
                    return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
                user = serializer.save()
                user.set_password(password)
                user.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginAPI(APIView):
    def post(self, request):
        dic ={}
        dic = {'csrftoken':'sss'}
        email = request.data.get('email')
        password = request.data.get('password')
        user_type = request.data.get('user_type')
        print(user_type)
        print(email, password)
        user = User.objects.filter(email=email).first()
        if user is not None:
            if user.is_farmer and user_type == 'farmer':
                if user.check_password(password):
                    login(request, user)
                    print(request.user)
                    print(request.META)
                    dic['csrftoken']= request.META['CSRF_COOKIE']
                    print(dic.items())
                    return Response({
                        'status': 'success',
                        'IsCustomer': user.is_customer,
                        'IsFarmer': user.is_farmer,
                        'username':user.username,
                        'userId':user.id,
                        'message': 'login successful as a farmer',
                        'csrftoken':dic['csrftoken']
                    })
                else:
                    raise AuthenticationFailed('Incorrect Password')
            elif user.is_customer and user_type == 'customer':
                if user.check_password(password):
                    login(request, user)
                    print(request.user)
                    print(request.META)
                    dic['csrftoken']= request.META['CSRF_COOKIE']
                    print(dic.items())
                    return Response({
                        'status': 'success',
                        'IsCustomer': user.is_customer,
                        'IsFarmer': user.is_farmer,
                        'username':user.username,
                        'userId':user.id,
                        'message': 'login successful as a customer',
                        'csrftoken': dic['csrftoken']
                    })
                else:
                    raise AuthenticationFailed('Incorrect Password')
            else:
                raise AuthenticationFailed(
                    'Please select either customer or farmer')
        else:
            raise AuthenticationFailed('user not found')



class VegitablesList(generics.ListAPIView):
    queryset = Product.objects.filter(category='V')
    serializer_class = ProductSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data
        for item in data:
            item['product_image'] = request.build_absolute_uri(
                item['product_image'])
        return Response(data)


class FruitsList(generics.ListAPIView):
    queryset = Product.objects.filter(category='F')
    serializer_class = ProductSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data
        for item in data:
            item['product_image'] = request.build_absolute_uri(
                item['product_image'])
        return Response(data)


class Veglistbypin(APIView):
  def get(self, request, pin):
        product = Product.objects.filter(category='V',pincode = pin)
        serializer = ProductSerializer(product,many = True)
        data=serializer.data
        for item in data:
           item['product_image']=request.build_absolute_uri(item['product_image'])
        return Response(data, status=200)

class Frtlistbypin(APIView):
  def get(self, request, pin):
        product = Product.objects.filter(category='F',pincode = pin)
        serializer = ProductSerializer(product,many = True)
        data=serializer.data
        for item in data:
           item['product_image']=request.build_absolute_uri(item['product_image'])
        return Response(data, status=200)


class add_to_cartAPI(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        cart = Cart.objects.filter(user=user)
        serializer = CartSerializer(cart, many=True)
        return Response(serializer.data)

class add_to_cartPost(APIView):

  permission_classes = [permissions.IsAuthenticated]

  def post(self, request):

    user = request.user

    serializer = CartSerializer(data=request.data)

   

    if serializer.is_valid():

      item = serializer.save(user=user)

      return Response(CartSerializer(item).data, status=status.HTTP_201_CREATED)

   

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Deletecart(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def delete(self, request, pk):
        try:
            cart_item = Cart.objects.get(pk=pk, user=request.user)
            cart_item.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Cart.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        


class AddProductsView(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProductSerializer


class ProductDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        product = Product.objects.get(pk=pk)
        serializer = ProductSerializer(product)
        return Response(serializer.data, status=200)


class AddressAPI(APIView):
    def get(self, request, pk=None, format=None):
        user = request.user
        cus = Customer.objects.filter(user=user)
        serializer = CustomerSerializer(cus, many=True)
        return Response(serializer.data)


class ProfileApi(APIView):
    def post(self, request, format=None):
        user = request.user
        serializer = CustomerSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.save()
            data.user = user
            data.save()
            return Response({'msg': 'Data Created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BuyNowView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = BuyNowSerializer(data=request.data)
        if serializer.is_valid():
            # Process the purchase
            return Response({"message": "Purchase successful"}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




from rest_framework.authentication import SessionAuthentication
from rest_framework import permissions



class IsCustomer(permissions.BasePermission):
    def has_permission(self, request, view):
        print(request.user, request.user.is_customer ,request.user.is_farmer,  '----------')
        return request.user.is_customer and request.user.is_farmer==False
    
class IsFarmer(permissions.BasePermission):
    def has_permission(self, request, view):
        print(request.user, request.user.is_customer ,request.user.is_farmer,  '----------')
        return request.user.is_customer==False and request.user.is_farmer

class OrderPlacedApiCustomer(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes=[IsCustomer]
    def get(self, request, pk=None, format=None):
        print(request.user, 'dataaaa')
        user = request.user
        # userobj = User.objects.filter(customer__user=user)
        # print(userobj)  
        cus = OrderPlaced.objects.filter(customer__user=user)
        serializer = PlaceOrderSerializer(cus, many=True)
        return Response(serializer.data)
        
        
class OrderPlacedApiFarmer(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes=[IsFarmer]
    def get(self, request, pk=None, format=None):
        user = request.user
        userobj = User.objects.filter(username=user)
        print(userobj)  
        cus = OrderPlaced.objects.filter(user=user)
        serializer = PlaceOrderSerializer(cus, many=True)
        return Response(serializer.data)          



    # def post(self, request, format=None):
    #     user = request.user
    #     serializer = PlaceOrderSerializer(data=request.data)
    #     if serializer.is_valid():
    #         data = serializer.save()
    #         data.user = user
    #         data.save()
    #         return Response({'msg': 'Data Created'}, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




# class PasswordChangeView(APIView):
#    # permission_classes=[IsAuthenticated]
#     def put(self, request, format=None):
#         # authenticate user
#         user = authenticate(email=request.user.email,
#                             password=request.data['old_password'])
#         if user is None:
#             return Response({'error': 'Invalid old password'})
#         new_password = request.data['new_password']
#         if not user.check_password(new_password):
#             if len(new_password) < 8:
#                 return Response({'error': 'Password must be at least 8 characters'})
#             if not any(char.isdigit() for char in new_password):
#                 return Response({'error': 'Password must contain at least one digit'})
#             if not any(char.isupper() for char in new_password):
#                 return Response({'error': 'Password must contain at least one uppercase letter'})
#             if not any(char.islower() for char in new_password):
#                 return Response({'error': 'Password must contain at least one lowercase letter'})

#         user.set_password(new_password)
#         user.save()

#         return Response({'message': 'Password changed successfully'})


# User = get_user_model()








class PasswordChangeView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, format=None):
        user = request.user
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        # check if old password is correct
        if not user.check_password(old_password):
            return Response({'error': 'Invalid old password'}, status=status.HTTP_400_BAD_REQUEST)

        # validate the new password
        if len(new_password) < 8:
            return Response({'error': 'Password must be at least 8 characters'}, status=status.HTTP_400_BAD_REQUEST)
        if not any(char.isdigit() for char in new_password):
            return Response({'error': 'Password must contain at least one digit'}, status=status.HTTP_400_BAD_REQUEST)
        if not any(char.isupper() for char in new_password):
            return Response({'error': 'Password must contain at least one uppercase letter'}, status=status.HTTP_400_BAD_REQUEST)
        if not any(char.islower() for char in new_password):
            return Response({'error': 'Password must contain at least one lowercase letter'}, status=status.HTTP_400_BAD_REQUEST)

        # set the new password
        user.set_password(new_password)
        user.save()
        csrftoken = request.META['CSRF_COOKIE']
        return Response({'message': 'Password changed successfully','csrftoken':csrftoken}, status=status.HTTP_200_OK)





class LogoutAPI(APIView):
    def post(self, request, format=None):
        logout(request)
        # csrftoken = request.META['CSRF_COOKIE']
        return Response({"MSG":"log out done"},status=status.HTTP_204_NO_CONTENT)

    
class CheckOutApi(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        cart = Cart.objects.filter(user=user)
        ls = []
        service_charge = 40.0
        cart_data = Cart.objects.all()
        for i in cart_data:
            d = {}
            d['quantity'] = i.quantity
            d['price'] = i.product.discountd_price*i.quantity
            d['product'] = i.product
            ls.append(d)
        total_price = sum(item['price'] for item in ls)
        total_amo = total_price+service_charge
       
        CheckOut.total_amount = total_amo
        data1 = CheckOutSerializer(ls,many=True)
        response_data = {
            'status': 'Success'
        }

        return Response((data1.data,{"total_amount":CheckOut.total_amount}))
    


class RelatedProducts(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, pk):
        product = Product.objects.get(id=pk)
        name = product.title
        print('name of product',name)
        products = Product.objects.filter(title=name).exclude(id=pk)
        serializer = ProductSerializer(products,many=True)
        return Response(serializer.data, status=200)
    


@method_decorator(csrf_exempt, name='dispatch')
class FeedbackListCreateView(generics.ListCreateAPIView):
    queryset=Feedback.objects.all()
    serializer_class=FeedbackSerializer     




class ForgotPasswordView(views.APIView):
    def post(self, request, format=None):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'User with given email does not exist.'},
                            status=status.HTTP_404_NOT_FOUND)

        token = default_token_generator.make_token(user)

        subject = 'Reset your password'
        message = render_to_string('password_reset_email.html', {
            'user': user,
            'token': token,
            'protocol': 'https' if request.is_secure() else 'http',
            'domain': request.get_host(),

        })
        print(email)
        send_mail(subject, message, 'dastagirig1996@gmail.com', [email])

        return Response({'detail': 'Password reset email sent.'},
                        status=status.HTTP_200_OK)


User = get_user_model()
class PasswordResetConfirmView(views.APIView):
    def post(self, request, uidb64, token, format=None):
        try:
            uid = int(uidb64)
            user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        print(user)
        if user is not None and default_token_generator.check_token(user, token):
            new_password = request.data['new_password']
            confirm_password = request.data["confirm_password"]
            if new_password == confirm_password:
                if not user.check_password(new_password):
                    if len(new_password) < 8:
                        return Response({'error': 'Password must be at least 8 characters'})
                    if not any(char.isdigit() for char in new_password):
                        return Response({'error': 'Password must contain at least one digit'})
                    if not any(char.isupper() for char in new_password):
                        return Response({'error': 'Password must contain at least one uppercase letter'})
                    if not any(char.islower() for char in new_password):
                        return Response({'error': 'Password must contain at least one lowercase letter'})

                user.set_password(new_password)
                user.save()
            else:
                return Response({'detail': 'Password not matching'},
                            status=status.HTTP_400_BAD_REQUEST)
            return Response({'detail': 'Password has been reset successfully.'},status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Invalid reset link.'},
                            status=status.HTTP_400_BAD_REQUEST)
        




# class IsProductOwner(permissions.BasePermission):
#     def has_object_permission(self, request, view, obj):
#         return obj.farmer == request.user.farmer


# class UpdateData(viewsets.ModelViewSet):
#     queryset=Product.objects.all()
#     serializer_class=ProductSerializer
#     permission_classes = [permissions.IsAuthenticated, IsProductOwner]