from django.db import models

from django.db import models
from django.contrib.auth.models import User,AbstractUser
from django.core.validators import MaxValueValidator,MinValueValidator

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    phone_no = models.IntegerField(blank=False, unique= True, null=True)
    Address = models.TextField(max_length=200)
    Pincode = models.IntegerField(null=True)
    is_farmer = models.BooleanField(default=False)
    is_customer = models.BooleanField(default=False)
    is_deliverer = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.first_name



# from django.db.models.fields import CharField
# from django.utils.translation import gettext_lazy as _
# from .constants import PaymentStatus

STATE_CHOICES = (('KA', 'Karnataka'),
('AP', 'Andhra Pradesh'),
('KL', 'Kerala'),
('TN', 'Tamil Nadu'),
('MH', 'Maharashtra'),
('UP', 'Uttar Pradesh'),
('GA', 'Goa'),
('GJ', 'Gujarat'),
('RJ', 'Rajasthan'),
('HP', 'Himachal Pradesh'),
('TG', 'Telangana'),
('AR', 'Arunachal Pradesh'),
('AS', 'Assam'), ('BR', 'Bihar'),
('CT', 'Chhattisgarh'),
('HR', 'Haryana'),
('JH', 'Jharkhand'),
('MP', 'Madhya Pradesh'),
('MN', 'Manipur'),
('ML', 'Meghalaya'),
('MZ', 'Mizoram'),
('NL', 'Nagaland'),
('OR', 'Odisha'),
('PB', 'Punjab'),
('SK', 'Sikkim'),
('TR', 'Tripura'),
('UT', 'Uttarakhand'),
('WB', 'West Bengal'),
('AN', 'Andaman and Nicobar Islands'),
('CH', 'Chandigarh'),
('DH', 'Dadra and Nagar Haveli and Daman and Diu'),
('DL', 'Delhi'),
('JK', 'Jammu and Kashmir'),
('LD', 'Lakshadweep'),
('LA', 'Ladakh'),
('PY', 'Puducherry'))

class Customer(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    name=models.CharField(max_length=100)
    locality=models.CharField(max_length=100)
    city=models.CharField(max_length=20)
    pincode=models.IntegerField()
    state=models.CharField(choices=STATE_CHOICES,max_length=50)

    def __str__(self):
        return str(self.id)

CATEGORY_CHOICES=(
    ('V','Vegitable'),
    ('F','Fruits'),
    ('M','Milk'),
    ('Fi','Fish')
)

PRODUCTS = (
('Apple','Apple'),
('Banana','Banana'),
('Black Berries','Black Berries'),
('Blue Berries','Blue Berries'),
('Brinjal','Brinjal'),
('Bitter Gourd','Bitter Gourd'),
('Capsicum','Capsicum'),
('Cabbage','Cabbage'),
('Chili','Chili'),
('Cherries','Cherries'),
('Custard Apple','Custard Apple'),
('cluster Beans','cluster Beans'),
('Elephant Tusk Okra','Elephant Tusk Okra'),
('Flat Beans','Flat Beans'),
('Ginger','Ginger'),
('Grapes','Grapes'),
('Guava','Guava'),
('malabar Cucumber','malabar Cucumber'),
('Mango','Mango'),
('Onion','Onion'),
('Okra','Okra'),
('Orange','Orange'),
('Pine Apple','Pine Apple'),
('Carrot','Carrot'),
('Pear','Pear'),
('Plumps','Plumps'),
('Papaya','Papaya'),
('PumpKins','PumpKins'),
('Pigeon Pea','Pigeon Pea'),
('Potato','Potato'),
('Snake Cucumber','Snake Cucumber'),
('Tarmeric','Tarmeric'),
('Water Melon','Water Melon'),
('Water Spinach','Water Spinach'),
)
UNIT = (
('KG','KG'),
('ML','ML'),
('Dozen','Dozen'),
('Piece','Piece')
)

class Product(models.Model):
    farmer=models.ForeignKey(User,on_delete=models.CASCADE, null = True)
    title=models.CharField(choices=PRODUCTS,max_length=50)
    selling_price=models.FloatField()
    discountd_price=models.FloatField()
    description=models.TextField()
    category=models.CharField(choices=CATEGORY_CHOICES,max_length=2)
    quantity = models.IntegerField(default=1)
    Product_Added_date = models.DateTimeField(auto_now_add=True)
    product_image=models.FileField(upload_to='productimg')
    units = models.CharField(choices=UNIT,max_length=15,default='KG')
    pincode = models.IntegerField(null=True)

    def __str__(self):
        return self.title

class Cart(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    product=models.ForeignKey(Product,on_delete=models.CASCADE )
    quantity=models.IntegerField(default=1)

    def __str__(self):
        return str(self.id)

STATUS_CHOICES=(
    ('Accepted','Accepted'),
    ('Packed','Packed'),
    ('On the way','On the way'),
    ('Delivered','Delevered'),
    ('Cancle','Cancle')
)


class OrderPlaced(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    customer=models.ForeignKey(Customer,on_delete=models.CASCADE)
    product_name=models.ForeignKey(Product,on_delete=models.CASCADE)
    quantity=models.PositiveIntegerField(default=1)
    order_date=models.DateTimeField(auto_now_add=True)
    status=models.CharField(max_length=50,choices=STATUS_CHOICES,default='Pending')

    def __str__(self):
        return str(self.customer)


class OrderList(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    customer=models.ForeignKey(Customer,on_delete=models.CASCADE)
    product_name=models.ForeignKey(Product,on_delete=models.CASCADE)
    quantity=models.PositiveIntegerField(default=1)
    order_date=models.DateTimeField(auto_now_add=True)
    status=models.CharField(max_length=50,choices=STATUS_CHOICES,default='Pending')

class CheckOut(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)  # Change 'Product' to 'product' to match the field name in your serializer
    quantity = models.PositiveIntegerField(default=1)  # Update 'quantnity' to 'quantity' to fix a typo
    price = models.FloatField(default=0.0)
    total_amount = models.FloatField(default = 0.0)




#  FEEDBACK


class Feedback(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


