from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework.authentication import get_authorization_header

# Create your views here.
class RegisterView(APIView):
    authentication_classes = [TokenAuthentication]  # Token authentication for this view
    permission_classes = [IsAuthenticated]  # Ensure user is authenticated

    def post(self, request):
        # Debugging: print authorization header
        auth_header = get_authorization_header(request).decode('utf-8')
        print("Authorization Header:", auth_header)  # Optional for debugging

        # Check if the user is authenticated and if the ID is 1 (Admin)
        if request.user.id != 1:
            return Response({'error': 'You are not authorized to Register. Only Admin Can Create New Users'}, status=401)

        # Extracting data from the request
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        username = request.data.get('username')  # Username will be unique
        password = request.data.get('password')


        # Check if the username already exists
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists! , Come up with a different username'}, status=400)

        # Create a new user
        user = User.objects.create_user(username=username, password=password, first_name = first_name, last_name = last_name)

        # Generate or retrieve a token for the user
        token, _ = Token.objects.get_or_create(user=user)

        # Return the response with the token
        return Response({'token': token.key, 'message': 'User registered successfully!'})
class LoginView(APIView):
    authentication_classes = []  # No authentication for login
    permission_classes = []  # No permission restriction for login

    def post(self, request):
        id = request.data.get('id')
        username = request.data.get('username')
        password = request.data.get('password')

        # Check if username or password is empty
        if not username or not password:
            return Response({"error": "Fields cannot be empty"}, status=400)

        # Authenticate user
        user = authenticate(username=username, password=password)
        print(user)
        if user:
            # Generate or retrieve token
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        else:
            return Response({'error': 'Invalid credentials'}, status=401)
class ProfileView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        
        user = request.user
        return Response({'username': user.username})
# Only User with ID 1 can delete a user (Admin)
class DeleteUser(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        # Print for debugging: authorization header
        auth_header = get_authorization_header(request).decode('utf-8')
        print("Authorization Header:", auth_header)

        # Check if the user is authenticated and if the ID is 1 (Admin)
        if request.user.id != 1:
            return Response({'error': 'You are not authorized to Delete any user. Only Admin Can'}, status=401)

        try:
            # Try to fetch the user to delete by ID
            user = User.objects.get(id=user_id)
            user.delete()  # Delete the user
            return Response({'message': 'User deleted successfully'}, status=200)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)       
class UserListView(APIView):
    authentication_classes = []
    permission_classes = []
    def get(self, request):
       
        user = User.objects.all().values('id', 'username', 'password', 'first_name', 'last_name')   #password is Django hash code protected
        return Response({'user': list(user)}, status=200)
class ResetPassword(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Check if the user is authenticated and if the ID is 1 (Admin)
        if request.user.id != 1:
            return Response({'error': 'You are not authorized to Register. Only Admin Can Create New Users'}, status=401)
        # Implement password reset logic here
        user_id = request.data.get('id')
        new_password = request.data.get('new_password')

        if not user_id or not new_password:
            return Response({'error': 'Fields cannot be empty'}, status=400)

        try:
            user = User.objects.get(id=user_id)
            user.set_password(new_password)
            user.save()
            return Response("Password reset successfully", status=200)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)
        



class UpdateView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            allowed_fields = ['first_name', 'last_name']
            updated_data = {field: request.data.get(field) for field in allowed_fields if request.data.get(field) is not None}
            for field, value in updated_data.items():
                setattr(user, field, value)

            user.save()
            return Response({'message': 'User updated successfully'}, status=200)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=404)