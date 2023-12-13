from django.shortcuts import render

# Create your views here.
def HomePage(request):
    return render(request, 'index.html')

def ContactPage(request):
    return render(request, 'contact.html')








