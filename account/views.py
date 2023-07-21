from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import *
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view
import logging
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    logger = logging.getLogger(__name__)
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    logger.warning("Done Registration")
    return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  
  def post(self, request, format=None):
        logger = logging.getLogger(__name__)
        try:
            serializer = UserLoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                  
                  token = get_tokens_for_user(user)
                  logger.warning("Success")
                  return Response({'token': token, 'msg': 'Login Success'}, status=status.HTTP_200_OK)
      
            raise Exception('Email or Password is not Valid')
          
        except Exception as e:
                    
            logger.warning(f"Error occurred: {str(e)}")
            return Response( status=status.HTTP_404_NOT_FOUND)

class TestAPI(APIView):
    @api_view(["GET"])
    def test_api_method(request):
        logger = logging.getLogger(__name__)
        
        
        num1 = 5
        num2 = 9
        
        try:
            result = num1 + num2
            logger.info(f'Addition: {num1} + {num2} = {result}')
            if result > 5:
                result_condition = True
                logger.warning(f'Successful.\nResult: {result}')
            else:
                result_condition = False
                logger.error(f'Addition result is not greater than 5. Result: {result}')
        except Exception as e:
            logger.exception(f'Addition failed: {str(e)}')
            result_condition = False
        return Response({'data': result_condition}, status=status.HTTP_200_OK)


class UserProfileView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)
  
  
  

class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
  
 
  

  
  
  