from django.contrib import admin
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views

from django.urls import path
# from .views import CreateUserAPIView, ListUsersAPIView, UserDetailView,LoginAPIView,CustomeraddressAPI,ChangePasswordView
from django.urls import path, include
from rest_framework import routers
# from .views import CustomerViewSet,addcartApi


router = routers.DefaultRouter()
# router.register('product', ProductViewSet)
# router.register('customers', CustomerViewSet)
# router.register('cart',addcartApi)
router.register('updateData',views.UpdateData)
from .views import FeedbackListCreateView
urlpatterns = [

    path('userreg/', views.UserRegistrationAPI.as_view()),
    path('userlogin/', views.UserLoginAPI.as_view()),
    path('veglist/',views.VegitablesList.as_view(),name='home'),
    path('frtlist/',views.FruitsList.as_view(),name='home'),
    path("addtocart/",views.add_to_cartAPI.as_view()),
    path("addtocartpost/",views.add_to_cartPost.as_view()),
    path("deletecart/<int:pk>/",views.Deletecart.as_view()),
    path('addproducts/', views.AddProductsView.as_view(), name='add_products'),
    path('productdetails/<int:pk>/', views.ProductDetailView.as_view(), name='productdetails'),
    path('address/', views.AddressAPI.as_view(), name='AddressAPI'),
    path('profile/', views.ProfileApi.as_view(), name='profileAPI'),
    path('orders/',views.OrderPlacedApi.as_view()),
    path('orderlist/',views.OrderListApi.as_view()),
    path('veglistbypin/<int:pin>/',views.Veglistbypin.as_view(),name='home'),
    path('frtlistbypin/<int:pin>/',views.Frtlistbypin.as_view(),name='home'),
    # path('address/<int:pk>', views.AddressAPI.as_view(), name='AddressAPI'),
    path("relateproduct/<int:pk>/",views.RelatedProducts.as_view()),
    path('buynow/', views.BuyNowView.as_view()),
    path('password/',views.PasswordChangeView.as_view(),name='password'),
    path('forgotpassword/',views.ForgotPasswordView.as_view(),name='fpassword'),
    path('resetpassword/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='reset_password'),
    # Django's built-in password reset views
    path('password-reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uid>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('logout/',views.LogoutView.as_view(),name='logout'),
    path('checkout/',views.CheckOutApi.as_view(),name='checkout'),
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('cus_orders/',views.OrderPlacedApi.as_view()),
    path('feedback/', FeedbackListCreateView.as_view(), name='feedback'),
    # path('user/', views.UserDetailView.as_view()),
    #  path('users/', views.ListUsersAPIView.as_view()),
    # path('farmlogin/', views.FarmerLoginAPI.as_view()),
    path('', include(router.urls)),
    ]+static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)

    


