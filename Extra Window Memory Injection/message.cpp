#include <windows.h>

int main() {
    // Display a message box in the current process indicating the injection was successful
    MessageBoxW(
        NULL,                            // hWnd: No owner window specified
        L"Injected!",                    // lpText: Content of the message box
        L"ListPlanting",                 // lpCaption: Title of the message box
        MB_OK | MB_ICONINFORMATION       // uType: Button and icon type (OK button with information icon)
    );  
    return 0;

}
