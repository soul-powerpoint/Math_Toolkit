#include <stdio.h>
#include <raylib.h>

#define WIDTH 1600
#define HEIGHT 900

int main(int argc, char *argv[]) {
    InitWindow(WIDTH, HEIGHT, "cube");
    // DisableCursor();
    SetTargetFPS(120);

    Vector3 pos = {5, 0, 0};
    Vector3 target = {0, 0, 0};
    Vector3 up = {0, 0, 1};

    float fovy = 90;
    Camera3D cam = {pos, target, up, fovy, CAMERA_PERSPECTIVE};

    while (!WindowShouldClose()) {
        UpdateCamera(&cam, CAMERA_FREE);
        BeginDrawing();
        ClearBackground(BLACK);
        BeginMode3D(cam);

        printf("cam.position.x = %f\n", cam.position.x);
        printf("cam.position.y = %f\n", cam.position.y);
        printf("cam.position.z = %f\n", cam.position.z);
        printf("\n");

        Vector3 origin = {0, 0, 0};
        DrawCube(origin, 1, 1, 1, BLUE);
        DrawCubeWires(origin, 1, 1, 1, RED);

        EndMode3D();
        EndDrawing();
    }

    return 0;
}
