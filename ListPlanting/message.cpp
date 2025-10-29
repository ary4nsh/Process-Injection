#include <windows.h>

int main() {
    MessageBoxW(
        NULL,                        // No owner window
        L"Injected!",                // Message box content
        L"ListPlanting",             // Message box title
        MB_OK | MB_ICONINFORMATION   // Button and icon type
    );
    return 0;
}