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


User = get_user_model() 
class CustomerRegistrationAPI(APIView):
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
                user.is_customer = True
                user.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FarmerRegistrationAPI(APIView): 
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
                user.is_farmer = True
                user.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginAPI(APIView):
    def post(self, request):
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
                    return Response({
                        'status': 'success',
                        'IsCustomer': user.is_customer,
                        'IsFarmer': user.is_farmer,
                        'message': 'login successful as a farmer'
                    })
                else:
                    raise AuthenticationFailed('Incorrect Password')
            elif user.is_customer and user_type == 'customer':
                if user.check_password(password):
                    login(request, user)
                    print(request.user)
                    return Response({
                        'status': 'success',
                        'IsCustomer': user.is_customer,
                        'IsFarmer': user.is_farmer,
                        'message': 'login successful as a customer'
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


class Veglistbypin(generics.ListAPIView):
    pin = 509381
    queryset = Product.objects.filter(category='V', pincode=pin)
    serializer_class = ProductSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data
        for item in data:
            item['product_image'] = request.build_absolute_uri(
                item['product_image'])
        return Response(data)


class Frtlistbypin(generics.ListAPIView):
    pin = 509381
    queryset = Product.objects.filter(category='F', pincode=pin)
    serializer_class = ProductSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data
        for item in data:
            item['product_image'] = request.build_absolute_uri(
                item['product_image'])
        return Response(data)


class add_to_cartAPI(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        cart = Cart.objects.filter(user=user)
        serializer = CartSerializer(cart, many=True)
        return Response(serializer.data)


class AddProductsView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProductSerializer

    def post(self, request, format=None):
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            s = serializer.save()
            s.farmer = request.user
            s.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


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


class OrderPlacedApi(APIView):
    def get(self, request, pk=None, format=None):
        user = request.user
        cus = OrderPlaced.objects.filter(user=user)
        serializer = PlaceOrderSerializer(cus, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        user = request.user
        serializer = PlaceOrderSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.save()
            data.user = user
            data.save()
            return Response({'msg': 'Data Created'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OrderListApi(APIView):
    def get(self, request, pk=None, format=None):
        user = request.user
        cus = OrderList.objects.filter(user=user)
        serializer = PlaceOrderSerializer(cus, many=True)
        return Response(serializer.data)


class PasswordChangeView(APIView):
    def put(self, request, format=None):
        # authenticate user
        user = authenticate(email=request.user.email,
                            password=request.data['old_password'])
        if user is None:
            return Response({'error': 'Invalid old password'})
        new_password = request.data['new_password']
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

        return Response({'message': 'Password changed successfully'})


User = get_user_model()


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
    def get(self, request, uidb64, token, format=None):
        try:
            uid = int(uidb64)
            user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and default_token_generator.check_token(user, token):
            request.session['reset_user_id'] = user.id
            form = SetPasswordForm(user)
            return render(request, 'reset_password.html', {'form': form.as_p()})
        else:
            return Response({'detail': 'Invalid reset link.'},
                            status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, uidb64, token, format=None):
        try:
            uid = int(uidb64)
            user = User.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and default_token_generator.check_token(user, token):
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                user = form.user
                login(request, user)
                request.session.pop('reset_user_id', None)
                return Response({'detail': 'Password has been reset successfully.'},
                                status=status.HTTP_200_OK)
            else:
                return render(request, 'reset_password.html', {'form': form.as_p()})
        else:
            return Response({'detail': 'Invalid reset link.'},
                            status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({"detail": "You have been logged out."})
    
class CheckOutApi(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request):
        user = request.user
        cart = Cart.objects.filter(user=user)
        d = {}
        service_charge = 40.0
        cart_data = Cart.objects.all()
        for i in cart_data:
            d['quantity'] = i.quantity
            d['dprice'] = i.product.discountd_price
            d['pname'] = i.product

        price = d['quantity'] * d['dprice']
        total_amount = service_charge + price
        CheckOut.total_amount = total_amount
        CheckOut.price = price
        # checkk = CheckOut.objects.create(user=user, product=d['pname'], quantity=d['quantity'], price=d['dprice'], total_amount=total)  # Use correct field names here
        # checkk.save()
        data1 = CheckOut.objects.filter(user=user).order_by('-id')[:1].get()
        print(data1, 'dataaaa')
        # Serialize the CheckOut object using CheckOutSerializer
        serializer = CheckOutSerializer(data1)

        response_data = {
            'status': 'Success',
            'data': serializer.data
        }

        return Response(response_data)
    
class OrderListApi(APIView):
    def get(self,request, format=None): 
        print('user',request.user)
        obj = User.objects.get(username=request.user)
        cus = OrderPlaced.objects.filter(user_id=obj.id)
        print(cus)
        serializer = PlaceOrderSerializer(cus, many=True)
        print(serializer)
        return Response(serializer.data)

class RelatedProducts(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, pk):
        product = Product.objects.get(id=pk)
        name = product.title
        print('name of product',name)
        products = Product.objects.filter(title=name).exclude(id=pk)
        serializer = ProductSerializer(products,many=True)
        return Response(serializer.data, status=200)
'''

# class LogoutView(APIView):
#     authentication_classes = [authentication.TokenAuthentication]
#     permission_classes = [permissions.IsAuthenticated]

#     def post(self, request):
#         request.user.auth_token.delete()
#         return Response({"detail": "You have been logged out."})
class FarmerLoginAPI(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        print(email,password)
        user = User.objects.filter(email=email).first()
        if user is not None:
            if user.is_farmer:
                if user.check_password(password):
                    login(request, user)
                    print(request.user)
                    return Response({
                        'status': 'success',
                        'data': {'user': email},
                        'is_superuser': user.is_superuser,
                        'is_staff': user.is_staff,
                        'message': 'login successful'
                    })
                else:
                    raise AuthenticationFailed('Incorrect Password')
            else:
                raise AuthenticationFailed('user not registered as farmer')
        else:
            raise AuthenticationFailed('user not found')
class FarmerRegistrationAPI(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer

    def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                print("before", serializer.validated_data)
                password = serializer.validated_data.pop('password')
                print(password)
                confirm_password = serializer.validated_data.pop(
                    'confirm_password')
                print(confirm_password)
                print("After", serializer.validated_data)
                if password != confirm_password:
                    return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
                user = serializer.save()
                user.set_password(password)
                user.is_farmer = True
                user.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


'''


# class OrderListApi(APIView):
#     def get(self,request, pk=None, format=None):
#         user = request.user
#         cus = OrderList.objects.get(user=user)
#         user.username
# class ListUsersAPIView(generics.ListAPIView):
#     permission_classes = (permissions.IsAuthenticated,)
#     serializer_class = UserSerializer
#     def get_queryset(self):
#         if self.request.user.is_staff:
#             return User.objects.all()
#         return User.objects.filter(id=self.request.user.id)
# class UserDetailView(APIView):
#     permission_classes = (permissions.IsAuthenticated)
#     def get(self, request):
#         serializer = UserSerializer(request.user)
#         return Response(serializer.data)
#     def patch(self, request):
#         serializer = UserSerializer(request.user, data=request.data, partial=True)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(serializer.data)
# class CustomerViewSet(viewsets.ModelViewSet):
#     permission_classes = [IsAuthenticated]
#     queryset = Customer.objects.all()
#     serializer_class = CustomerSerializer
# # class add_to_cartAPI(APIView):
# #     permission_classes=[IsAuthenticated]
# #     def get(self, request, pk=None, format=None):
# #         id = pk
# #         if id is not None:
# #             cart = Cart.objects.get(id=id)
# #             serializer = CartSerializer(cart)
# #             return Response(serializer.data)
# #         cart = Cart.objects.all()
# #         print(request.data)
# #         serializer = CartSerializer(cart, many=True)
# #         return Response(serializer.data)
# #     def post(self, request, format=None):
# #         serializer = CartSerializer(data=request.data)
# #         if serializer.is_valid():
# #             serializer.save()
# #             return Response({'msg': 'Data Created'}, status=status.HTTP_201_CREATED)
# #         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
# # class check_out(APIView):
# #     def get(self, request, pk=None, format=None):
# #         id = pk
# #         if id is not None:
# #             cart = Cart.objects.get(id=id)
# #             serializer = checkoutSerializer(cart)
# #             return Response(serializer.data)
# #         cart = Cart.objects.all()
# #         print(request.data)
# #         serializer = checkoutSerializer(cart, many=True)
# #         return Response(serializer.data)


# ######################  model viewset Api  ########################################

# from rest_framework import viewsets
# from .serializers import ProductSerializer
# from .models import Product

# # class ProductViewSet(viewsets.ModelViewSet):
# #     serializer_class = ProductSerializer
# #     permission_classes = [IsAuthenticated]
# #     queryset = Product.objects.all()


# class addcartApi(viewsets.ModelViewSet):
#     serializer_class=CartSerializer
#     permission_classes=[IsAuthenticated]
#     queryset= Cart.objects.all()
