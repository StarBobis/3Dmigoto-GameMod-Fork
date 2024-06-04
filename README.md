# 3Dmigoto-Armor (for game mod)
This is a special fork version of 3dmigoto repo, Latest fork date: 2023-12-24

To keep update with original 3Dmigoto project,these fork version of 3Dmigoto-Armor series project will show 
the fork date in project name ,so you can know what latest features it include and what not.

This fork is mainly to solve the game mod problem.

Notice: This project is a toy for pure pleasure, will no released version of d3d11.dll published, you need to compile it yourself.

# Problems
- Notice: If you open Version in resource view,the entire project will break and can't compile anymore,version can
only be edited in versions.h. I will try fix this later but before that don't open it in resource view.

- Notice: I have modified a lot of code for better game mod support, it will not fully work same as original 3dmigoto.

# Features

- Dynamic d3d11 desc byte increase with model's vertex number to avoid memory waste and avoid possible out of memory error.
- Increase default d3d11 desc byte width to 380k(380 * 1000 * 40) as GIMI's design.
- Fully Compatible with GIMI's d3d11.dll (store command supported).
- Transfer to VS2022 ,PlatformToolsetV143, Win10SDK latest.

# Discord
You can send me feedback or ask question about 3Dmigoto source code in this discord channel:

Server invite link: https://discord.gg/Cz577BcRf5


# Credit to 3Dmigoto repository
Original 3Dmigoto repository: https://github.com/bo3b/3Dmigoto


Without their original 3dmigoto repo the game mod version will be impossible.
Huge thanks to Chiri,DarkStarSword,bo3b and 3Dmigoto original author group.

