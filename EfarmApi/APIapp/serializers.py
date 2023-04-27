from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import *
from rest_framework import serializers
# from .models import Product,Cart

User = get_user_model()
class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'password', 'confirm_password','phone_no','Address', 'Pincode','is_customer','is_farmer' ]
        extra_kwargs = {'password': {'write_only': True}}
    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone_no=validated_data.get('phone_no', ''),
            Address=validated_data.get('Address', ''),
            Pincode=validated_data.get('Pincode', ''),
            is_farmer=validated_data.get('is_farmer', False),
            is_customer=validated_data.get('is_customer', False),
            is_deliverer=validated_data.get('is_deliverer', False)     
        )
        return user
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError('Passwords do not match')
        return data
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already exists')
        return value
    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    def validate_phone_no(self, value):
        if len(str(value)) != 10:
            raise serializers.ValidationError("Phone number should be of 10 digits")
        return value
    def validate_Pincode(self, value):
        if len(str(value)) != 6:
            raise serializers.ValidationError("Pincode should be of 6 digits")
        
        return value
    

    

class CartSerializer(serializers.ModelSerializer):
    class Meta:
        model=Cart
        fields= '__all__'


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ('id', 'title', 'selling_price', 'discountd_price', 'description', 'category', 'quantity', 'product_image')
        exclude = ['farmer']
    def create(self, validated_data):      
        return Product.objects.create(**validated_data)

class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model=Customer
        fields="__all__"

class BuyNowSerializer(serializers.Serializer):
    product_id = serializers.IntegerField()
    quantity = serializers.IntegerField()
    # payment_method = serializers.CharField()
    # billing_address = serializers.CharField()
    shipping_address = serializers.CharField()


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model=Customer
        fields="__all__"


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = '__all__'



class PlaceOrderSerializer(serializers.ModelSerializer):
    class Meta:
        model=OrderPlaced
        fields="--all__"


class OrderListSerializer(serializers.ModelSerializer):
    class Meta:
        model=OrderPlaced
        fields="__all__"



class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class CheckOutSerializer(serializers.ModelSerializer):
    # product = ProductSerializer()
    
    class Meta:
        model = CheckOut
        fields = ['product','quantity','price','total_amount']


