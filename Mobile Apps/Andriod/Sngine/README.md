
## Getting Started
These instructions will help you get your Sngine WebView copy up and running on your local machine for development and testing purposes.

### Requirement
The project requires minimum Android API 21+ (5.0 Lollipop) SDK to test. We use Android Studio (latest release by time last update 3.4.1) for this.

### Test Run
Try cleaning and rebuilding the project in your programming environment, once you are done fixing any error (incase of one), you'll be ready to look into the project.

### Permissions
You can remove any of the following requests if you do not need them or you can disable any feature using easy setup variables. Currently, these permissions are must for default variables to work properly.
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
<uses-permission android:name="android.permission.CAMERA"/>
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.VIBRATE" />
```
`INTERNET` permission is required if you are requesting a weburl or webpage.
`WRITE_EXTERNAL_STORAGE` is required for camera photo creation, if you have enabled `SngineApp_FUPLOAD` and `SngineApp_CAMUPLOAD` to upload image files.

### Easy Setup
Once your project is ready, here are some important config variables that you can adjust as per your app requirements.

#### Permission variables
```kotlin
static boolean SngineApp_JSCRIPT     = true     //enable JavaScript for webview
static boolean SngineApp_FUPLOAD     = true     //upload file from webview
static boolean SngineApp_CAMUPLOAD   = true     //enable upload from camera for photos
static boolean SngineApp_ONLYCAM     = false    //incase you want only camera files to upload
static boolean SngineApp_MULFILE     = true     //upload multiple files in webview
static boolean SngineApp_LOCATION    = true     //track GPS locations
static boolean SngineApp_RATINGS     = true     //show ratings dialog; auto configured, edit method get_rating() for customizations
static boolean SngineApp_PULLFRESH   = true     //pull refresh current url
static boolean SngineApp_PBAR        = true     //show progress bar in app
static boolean SngineApp_ZOOM        = false    //zoom control for webpages view
static boolean SngineApp_SFORM       = false    //save form cache and auto-fill information
static boolean SngineApp_OFFLINE     = false    //whether the loading webpages are offline or online
static boolean SngineApp_EXTURL      = true     //open external url with default browser instead of app webview
```
#### Security variables
```kotlin
static boolean SngineApp_CERT_VERIFICATION   = true    //verify whether HTTPS port needs certificate verification
```
#### Configuration variables
Complete URL of your website, landing page or local file as `file:///android_res/dir/file.html`
```kotlin
Sngine_URL      = "https://demo.sngine.com"    //domain, or directory or locating to any root file
```

If file upload enabled, you can define its extention type, default is `*/*` for all file types;

Use `image/*` for image types; check file type references on web for custom file type
```kotlin
Sngine_F_TYPE   = "*/*"
```

## Getting GPS Location
If `SngineApp_LOCATION = true` then the app will start requesting GPS locations of the device on regular basis and all of the recorded data will be sent to the webpage in form of cookies, with updated live GPS locations.
```kotlin
COOKIE "lat" for latitude
COOKIE "long" for longitude
```
